"""Requester acceptance: actual config/API/worker with synthetic data and blocked I/O."""

from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import Mock, patch

from pydantic import ValidationError


def scope(rate=1.0):
    now = datetime.now(UTC)
    return {
        "hosts": ["127.0.0.1"],
        "allowed_origins": ["http://127.0.0.1:8766"],
        "allowed_paths": ["/"],
        "excluded_paths": [],
        "allowed_cidrs": ["127.0.0.1/32"],
        "request_rate": rate,
        "starts_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }


class ConfigContract(TestCase):
    def test_current_ui_payload_and_legacy_names_have_one_canonical_shape(self):
        from aegis.schemas import ScanConfig

        payload = {
            "mode": "standard",
            "depth": 3,
            "rate": 0.1,
            "tags": "cve,tech",
            "tools": ["crawler", "nuclei"],
        }
        config = ScanConfig.model_validate(payload)
        self.assertEqual(config.model_dump() | payload, config.model_dump())
        legacy = ScanConfig.model_validate({"crawler_depth": 3, "rate_limit": 0.1})
        self.assertEqual(legacy.model_dump()["depth"], 3)
        self.assertEqual(legacy.model_dump()["rate"], 0.1)
        self.assertNotIn("rate_limit", legacy.model_dump())

    def test_invalid_and_ambiguous_inputs_are_rejected(self):
        from aegis.schemas import ScanConfig

        for payload in ({"rate": value} for value in [True, "1", 0, -1, 150, float("nan"), float("inf")]):
            with self.subTest(payload=payload), self.assertRaises(ValidationError):
                ScanConfig.model_validate(payload)
        for payload in (
            {"depth": True},
            {"depth": 1.5},
            {"depth": 6},
            {"depth": 2, "crawler_depth": 3},
            {"rate": 1, "rate_limit": 2},
            {"tools": ["unknown"]},
            {"tools": ["nmap", "nmap"]},
            {"tags": "cve;command"},
            {"tags": "x" * 513},
            {"severities": "critical,unknown"},
            {"mode": "passive", "tools": ["nmap"]},
            {"extra_option": True},
        ):
            with self.subTest(payload=payload), self.assertRaises(ValidationError):
                ScanConfig.model_validate(payload)


class ControlledProduct(TestCase):
    def setUp(self):
        self.guard = ExitStack()
        self.addCleanup(self.guard.close)
        for operation in (
            "socket.socket.connect",
            "socket.getaddrinfo",
            "subprocess.run",
            "subprocess.Popen",
            "os.fork",
        ):
            self.guard.enter_context(patch(operation, side_effect=AssertionError("Unexpected external I/O")))
        from fastapi.testclient import TestClient

        from aegis.api import create_app
        from aegis.auth import provision_owner
        from aegis.config import Settings

        folder = TemporaryDirectory(prefix="sharay-scan-config-")
        self.addCleanup(folder.cleanup)
        settings = Settings(Path(folder.name), start_worker=False)
        self.app = create_app(settings)
        self.sessions = self.app.state.sessions
        self.addCleanup(self.app.state.engine.dispose)
        password = "Synthetic-config-password-761!"
        with self.sessions() as db:
            owner = provision_owner(db, "configowner", password)
            self.owner_id, self.org_id = owner.id, owner.organization_id
            db.commit()
        self.client = TestClient(self.app, base_url=settings.origin)
        self.addCleanup(self.client.close)
        self.client.headers["origin"] = settings.origin
        login = self.client.post("/api/v1/auth/login", json={"username": "configowner", "password": password})
        self.assertEqual(login.status_code, 200)
        self.client.headers["x-csrf-token"] = login.json()["csrf_token"]
        project = self.client.post("/api/v1/projects", json={"name": "Synthetic config"})
        self.assertEqual(project.status_code, 201)
        self.project_id = project.json()["id"]
        self.worker_counter = 0
        target = self.client.post(
            f"/api/v1/projects/{self.project_id}/targets",
            json={"url": "http://127.0.0.1:8766/", "scope": scope()},
        )
        self.assertEqual(target.status_code, 201)
        self.target_id = target.json()["id"]
        approval = self.client.post(
            f"/api/v1/targets/{self.target_id}/approve",
            json={
                "acknowledgement": "I authorize this target within the displayed scope",
                "expected_scope_version": 1,
            },
        )
        self.assertEqual(approval.status_code, 200)

    def launch(self, config=None, profile="safe_http", key="synthetic-config-1"):
        payload = {
            "target_id": self.target_id,
            "expected_scope_version": 1,
            "idempotency_key": key,
            "profile": profile,
        }
        if config is not None:
            payload["config"] = config
        return self.client.post("/api/v1/assessments", json=payload)

    def test_api_snapshots_explicit_and_default_rates_without_changing_scope(self):
        from aegis.models import Assessment, Target

        for index, config in enumerate(({"rate": 0.1}, {})):
            response = self.launch(config, key=f"synthetic-rate-{index}")
            self.assertEqual(response.status_code, 201, response.text)
            with self.sessions() as db:
                row = db.get(Assessment, response.json()["id"])
                self.assertEqual(row.scope_snapshot["scan_config"]["rate"], 0.1 if index == 0 else 1.0)
                self.assertEqual(db.get(Target, self.target_id).scope["request_rate"], 1.0)

    def test_api_rejects_rate_above_approved_scope(self):
        response = self.launch({"rate": 2.0})
        self.assertEqual(response.status_code, 422, response.text)

    def test_idempotency_cannot_reuse_a_different_profile_or_config(self):
        first = self.launch({"rate": 0.5})
        self.assertEqual(first.status_code, 201, first.text)
        repeated = self.launch({"rate_limit": 0.5})
        self.assertEqual(repeated.status_code, 201, repeated.text)
        self.assertEqual(repeated.json()["id"], first.json()["id"])
        self.assertEqual(self.launch({"rate": 0.25}).status_code, 409)
        self.assertEqual(self.launch({"rate": 0.5}, profile="comprehensive").status_code, 409)

    def test_unavailable_profiles_and_non_rate_local_options_are_rejected(self):
        self.assertEqual(self.launch({"rate": 1}, profile="comprehensive").status_code, 422)
        self.assertEqual(self.launch({"rate": 1}, profile="approved_templates").status_code, 422)
        self.assertEqual(self.launch({"tools": ["nmap"]}).status_code, 422)

    def test_malformed_snapshot_replay_is_a_conflict_without_new_work(self):
        from aegis.models import Assessment

        for index, snapshot in enumerate((None, [], "invalid", 7)):
            with self.subTest(snapshot=snapshot):
                key = f"synthetic-malformed-{index}"
                response = self.launch(key=key)
                self.assertEqual(response.status_code, 201)
                with self.sessions() as db:
                    row = db.get(Assessment, response.json()["id"])
                    row.scope_snapshot = snapshot
                    db.commit()
                self.assertEqual(self.launch(key=key).status_code, 409)

    def test_null_legacy_config_replays_the_same_scope_defaults(self):
        from aegis.models import Assessment

        response = self.launch()
        self.assertEqual(response.status_code, 201)
        with self.sessions() as db:
            row = db.get(Assessment, response.json()["id"])
            row.scope_snapshot = {**row.scope_snapshot, "scan_config": None}
            db.commit()
        self.assertEqual(self.launch().status_code, 201)

    def enqueue(self, config, profile="comprehensive", approved_rate=2.0):
        from aegis.models import Assessment

        self.worker_counter += 1
        with self.sessions() as db:
            row = Assessment(
                organization_id=self.org_id,
                project_id=self.project_id,
                target_id=self.target_id,
                created_by=self.owner_id,
                idempotency_key=f"synthetic-worker-{self.worker_counter}",
                profile=profile,
                scope_snapshot=scope(approved_rate)
                | {"target_url": "http://127.0.0.1:8766/", "scan_config": config},
                scope_version=1,
            )
            db.add(row)
            db.flush()
            identifier = row.id
            db.commit()
        return identifier

    def worker(self, identifier, host="example.test"):
        from aegis.models import Assessment
        from aegis.worker import run_one

        result = {"outcome": "completed", "observations": [], "findings": [], "checks": []}
        self.scan = Mock(return_value=result)
        self.resolve = Mock(return_value="192.0.2.1")
        with (
            patch("aegis.worker.check_execution_url", return_value=SimpleNamespace(host=host)),
            patch("aegis.worker.resolve_pinned", self.resolve),
            patch("aegis.worker.scan_comprehensive", self.scan),
            patch("aegis.worker.scan_live_nuclei", self.scan),
            patch("aegis.worker.scan", self.scan),
        ):
            self.assertTrue(run_one(self.sessions))
        with self.sessions() as db:
            return db.get(Assessment, identifier).status

    def test_worker_keeps_unadopted_profiles_blocked_before_dns(self):
        for profile in ("safe_http", "comprehensive", "approved_templates"):
            with self.subTest(profile=profile):
                identifier = self.enqueue({"rate": 2}, profile=profile)
                self.assertEqual(self.worker(identifier), "failed")
                self.scan.assert_not_called()
                self.resolve.assert_not_called()

    def test_worker_refuses_tool_options_in_local_profile(self):
        identifier = self.enqueue({"tools": ["nmap"]}, profile="safe_http")
        self.assertEqual(self.worker(identifier, host="127.0.0.1"), "failed")
        self.scan.assert_not_called()

    def test_malformed_snapshot_is_durably_failed_before_dispatch(self):
        from aegis.models import Assessment

        for snapshot in (None, [], "invalid", 7, {}):
            with self.subTest(snapshot=snapshot):
                identifier = self.enqueue({}, profile="safe_http")
                with self.sessions() as db:
                    row = db.get(Assessment, identifier)
                    row.scope_snapshot = snapshot
                    db.commit()
                try:
                    self.assertEqual(self.worker(identifier, host="127.0.0.1"), "failed")
                    self.scan.assert_not_called()
                    self.resolve.assert_not_called()
                finally:
                    with self.sessions() as db:
                        row = db.get(Assessment, identifier)
                        row.status = "failed"  # Keep a broken fixture out of the next subtest's queue.
                        db.commit()

    def test_invalid_stored_config_fails_before_dns_and_dispatch(self):
        identifier = self.enqueue({"rate": 3}, approved_rate=1)
        self.assertEqual(self.worker(identifier), "failed")
        self.scan.assert_not_called()
        self.resolve.assert_not_called()

    def test_fractional_external_rate_is_refused_without_rounding_up(self):
        identifier = self.enqueue({"rate": 0.1}, approved_rate=0.1)
        self.assertEqual(self.worker(identifier), "failed")
        self.scan.assert_not_called()
        self.resolve.assert_not_called()

    def test_loopback_scanner_receives_exact_lower_rate(self):
        identifier = self.enqueue({"rate": 0.1}, profile="safe_http", approved_rate=1)
        self.assertEqual(self.worker(identifier, host="127.0.0.1"), "completed")
        self.assertEqual(self.scan.call_args.args[0]["request_rate"], 0.1)


if __name__ == "__main__":
    main(verbosity=2)
