"""Versioned scope changes preserve authorization and historic evidence boundaries."""

import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import select

from aegis.auth import add_user
from aegis.models import Assessment, AuditEvent, Organization, ProjectMember, Target, User
from aegis.worker import run_one
from packages.scanner_adapters import scan as controlled_scan
from tests.product import test_api_workflow as workflow


class ScopeLifecycleTests(unittest.TestCase):
    # Reuse the controlled fixture without inheriting/rerunning the workflow suite.
    setUp = workflow.WorkflowTests.setUp
    tearDown = workflow.WorkflowTests.tearDown
    login = workflow.WorkflowTests.login
    scope = workflow.WorkflowTests.scope
    target = workflow.WorkflowTests.target
    launch = workflow.WorkflowTests.launch

    def update(self, target, **changes):
        return self.client.patch(
            f"/api/v1/targets/{target['id']}/scope",
            json={
                "url": target["url"],
                "scope": target["scope"],
                "expected_scope_version": target["scope_version"],
                **changes,
            },
        )

    def approve(self, target, version=None):
        return self.client.post(
            f"/api/v1/targets/{target['id']}/approve",
            json={
                "acknowledgement": "I authorize this controlled laboratory target",
                "expected_scope_version": version or target["scope_version"],
            },
        )

    def test_broad_scope_replacement_does_not_rewrite_historical_report_readiness(self):
        from tests.product.test_broad_scope import broad_scope

        target, _ = self.target()
        baseline = self.launch(target)
        self.assertTrue(run_one(self.sessions))
        route = f"/api/v1/reports/{baseline['id']}?format=json"
        before = self.client.get(route).json()
        replacement = broad_scope()
        revised = self.update(target, url="https://example.com/", scope=replacement)
        self.assertEqual(revised.status_code, 200, revised.text)
        self.assertIn("execution requires", revised.json()["execution_blocker"])
        after = self.client.get(route).json()
        self.assertEqual(before["target"], after["target"])
        self.assertEqual(before["scope"], after["scope"])
        self.assertEqual(before["observations"], after["observations"])

    def test_scope_edit_resets_approval_stops_queue_and_preserves_reports(self):
        target, project = self.target()
        baseline = self.launch(target)
        self.assertTrue(run_one(self.sessions))
        before = self.client.get(f"/api/v1/reports/{baseline['id']}?format=json").json()
        queued = self.launch(target)
        other, _ = self.target()
        unrelated = self.launch(other)
        replacement = target["scope"] | {"allowed_paths": ["/repaired"]}
        response = self.update(target, url=self.url + "repaired", scope=replacement)
        self.assertEqual(response.status_code, 200, response.text)
        revised = response.json()
        self.assertEqual(revised["scope_version"], 2)
        self.assertEqual(revised["verification_status"], "awaiting_authorization")
        self.assertIsNone(revised["authorized_by"])
        self.assertIsNone(revised["approved_at"])
        stopped = self.client.get(f"/api/v1/assessments/{queued['id']}").json()
        self.assertEqual(stopped["status"], "cancelled")
        self.assertTrue(stopped["cancel_requested"])
        self.assertIsNotNone(stopped["finished_at"])
        self.assertEqual(stopped["scope_version"], 1)
        self.assertEqual(stopped["scope_snapshot"], queued["scope_snapshot"])
        self.assertEqual(self.client.get(f"/api/v1/assessments/{unrelated['id']}").json()["status"], "queued")
        after = self.client.get(f"/api/v1/reports/{baseline['id']}?format=json").json()
        for field in ("target", "scope", "assessment", "findings", "observations"):
            self.assertEqual(before[field], after[field], field)
        self.assertEqual(after["target"]["url"], target["url"])
        self.assertEqual(after["target"]["scope_version"], 1)
        self.assertEqual(self.approve(revised, version=1).status_code, 409)
        self.assertEqual(
            self.client.post(
                "/api/v1/assessments",
                json={
                    "target_id": target["id"],
                    "idempotency_key": "fresh-unapproved",
                    "expected_scope_version": 2,
                },
            ).status_code,
            403,
        )
        self.assertEqual(self.approve(revised).status_code, 200)
        launched = self.launch(revised)
        self.assertEqual(launched["scope_version"], 2)
        with self.sessions() as db:
            event = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.action == "scope.updated", AuditEvent.resource_id == target["id"]
                )
            )
            self.assertEqual(event.detail["previous_scope_version"], 1)
            self.assertEqual(event.detail["scope_version"], 2)
            self.assertEqual(event.detail["previous_url"], target["url"])
            self.assertEqual(event.detail["previous_scope"], target["scope"])
        self.assertTrue(self.client.get("/api/v1/audit").json()["integrity_valid"])

    def test_noop_preserves_approval_and_queue(self):
        target, _ = self.target()
        approved = self.client.get(f"/api/v1/targets/{target['id']}").json()
        queued = self.launch(target)
        with self.sessions() as db:
            audit_count = len(list(db.scalars(select(AuditEvent))))
        response = self.update(approved)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), approved)
        self.assertEqual(self.client.get(f"/api/v1/assessments/{queued['id']}").json()["status"], "queued")
        with self.sessions() as db:
            self.assertEqual(len(list(db.scalars(select(AuditEvent)))), audit_count)

    def test_stale_edits_approvals_and_launches_leave_state_unchanged(self):
        target, _ = self.target()
        revised = self.update(target, scope=target["scope"] | {"excluded_paths": ["/private"]}).json()
        self.assertEqual(revised["scope_version"], 2)
        self.assertEqual(self.approve(revised).status_code, 200)
        approved = self.client.get(f"/api/v1/targets/{target['id']}").json()
        self.assertEqual(self.update(target).status_code, 409)
        self.assertEqual(self.approve(target).status_code, 409)
        self.assertEqual(
            self.client.post(
                "/api/v1/assessments",
                json={
                    "target_id": target["id"],
                    "idempotency_key": "stale-launch",
                    "expected_scope_version": 1,
                },
            ).status_code,
            409,
        )
        self.assertEqual(self.client.get(f"/api/v1/targets/{target['id']}").json(), approved)
        self.assertEqual(self.client.get("/api/v1/assessments").json()["total"], 0)

    def test_invalid_external_expired_and_unversioned_inputs_do_not_mutate(self):
        target, _ = self.target()
        approved = self.client.get(f"/api/v1/targets/{target['id']}").json()
        queued = self.launch(target)
        now = datetime.now(timezone.utc)
        expired = target["scope"] | {
            "starts_at": (now - timedelta(hours=1)).isoformat(),
            "expires_at": (now - timedelta(seconds=1)).isoformat(),
        }
        for change in (
            {"url": "https://unapproved.example/"},
            {"scope": expired},
            {"scope": target["scope"] | {"allowed_paths": ["/../private"]}},
        ):
            with self.subTest(change=next(iter(change))):
                self.assertEqual(self.update(target, **change).status_code, 422)
        for version in (None, True, "1", 0):
            with self.subTest(version=version):
                fields = {} if version is None else {"expected_scope_version": version}
                for method, route, data in (
                    (
                        "patch",
                        f"/targets/{target['id']}/scope",
                        {"url": target["url"], "scope": target["scope"]},
                    ),
                    (
                        "post",
                        f"/targets/{target['id']}/approve",
                        {"acknowledgement": "I authorize this controlled laboratory target"},
                    ),
                    (
                        "post",
                        "/assessments",
                        {"target_id": target["id"], "idempotency_key": "invalid-version"},
                    ),
                ):
                    self.assertEqual(
                        getattr(self.client, method)("/api/v1" + route, json=data | fields).status_code, 422
                    )
        self.assertEqual(self.client.get(f"/api/v1/targets/{target['id']}").json(), approved)
        self.assertEqual(self.client.get(f"/api/v1/assessments/{queued['id']}").json()["status"], "queued")

    def test_versioned_idempotency_replay_preserves_original_request(self):
        target, _ = self.target()
        original = self.launch(target, key="versioned-replay")
        revised = self.update(target, scope=target["scope"] | {"excluded_paths": ["/private"]}).json()
        replay = self.launch(target, key="versioned-replay")
        self.assertEqual(replay["id"], original["id"])
        self.assertEqual(replay["scope_snapshot"], original["scope_snapshot"])
        self.assertEqual(replay["status"], "cancelled")
        self.assertEqual(
            self.client.post(
                "/api/v1/assessments",
                json={
                    "target_id": target["id"],
                    "idempotency_key": "versioned-replay",
                    "expected_scope_version": revised["scope_version"],
                },
            ).status_code,
            409,
        )
        self.assertEqual(self.client.get("/api/v1/assessments").json()["total"], 1)

    def test_idempotency_replays_after_expiry_and_archival_without_new_dispatch(self):
        target, project = self.target()
        original = self.launch(target, key="expired-archived-replay")
        with patch("packages.security_policies.datetime") as clock:
            clock.now.return_value = datetime.now(timezone.utc) + timedelta(hours=2)
            replay = self.launch(target, key="expired-archived-replay")
            self.assertEqual(replay["id"], original["id"])
            fresh = self.client.post(
                "/api/v1/assessments",
                json={
                    "target_id": target["id"],
                    "idempotency_key": "fresh-expired",
                    "expected_scope_version": 1,
                },
            )
            self.assertEqual(fresh.status_code, 422)
        self.assertEqual(
            self.client.patch(f"/api/v1/projects/{project['id']}", json={"archived": True}).status_code, 200
        )
        replay = self.launch(target, key="expired-archived-replay")
        self.assertEqual(replay["id"], original["id"])
        fresh = self.client.post(
            "/api/v1/assessments",
            json={
                "target_id": target["id"],
                "idempotency_key": "fresh-archived",
                "expected_scope_version": 1,
            },
        )
        self.assertEqual(fresh.status_code, 409)
        self.assertEqual(self.client.get("/api/v1/assessments").json()["total"], 1)

    def test_concurrent_scope_edits_accept_exactly_one_reviewed_version(self):
        target, _ = self.target()
        clients = [
            TestClient(self.app, base_url=self.settings.origin, headers={"origin": self.settings.origin})
            for _ in range(2)
        ]
        barrier = threading.Barrier(3)
        results, errors = [], []

        def edit(client, excluded):
            try:
                barrier.wait(timeout=5)
                results.append(
                    client.patch(
                        f"/api/v1/targets/{target['id']}/scope",
                        json={
                            "url": target["url"],
                            "scope": target["scope"] | {"excluded_paths": [excluded]},
                            "expected_scope_version": 1,
                        },
                    )
                )
            except Exception as exc:
                errors.append(type(exc).__name__)

        threads = []
        try:
            for index, client in enumerate(clients):
                self.login(client)
                thread = threading.Thread(target=edit, args=(client, f"/private-{index}"))
                threads.append(thread)
                thread.start()
            barrier.wait(timeout=5)
            for thread in threads:
                thread.join(timeout=8)
                self.assertFalse(thread.is_alive(), "Concurrent scope update did not finish")
            self.assertEqual(errors, [])
            self.assertEqual(sorted(response.status_code for response in results), [200, 409])
            stored = self.client.get(f"/api/v1/targets/{target['id']}").json()
            self.assertEqual(stored["scope_version"], 2)
            self.assertEqual(
                stored["scope"],
                next(response.json()["scope"] for response in results if response.status_code == 200),
            )
            with self.sessions() as db:
                events = list(
                    db.scalars(
                        select(AuditEvent).where(
                            AuditEvent.action == "scope.updated", AuditEvent.resource_id == target["id"]
                        )
                    )
                )
                self.assertEqual(len(events), 1)
        finally:
            barrier.abort()
            for thread in threads:
                thread.join(timeout=8)
            for client in clients:
                client.close()

    def test_scope_edit_cancels_already_claimed_work_without_rewriting_snapshot(self):
        target, _ = self.target()
        assessment = self.launch(target)
        entered, release = threading.Event(), threading.Event()
        observed = []

        def scan(scope, url, cancelled, emit, *, request_starts=None):
            entered.set()
            if not release.wait(3):
                raise RuntimeError("Synthetic worker handshake timed out")
            observed.append((scope, url, cancelled()))
            return {"outcome": "completed", "observations": [], "findings": [], "checks": []}

        with patch("aegis.worker.scan", side_effect=scan):
            thread = threading.Thread(target=run_one, args=(self.sessions,))
            thread.start()
            try:
                self.assertTrue(entered.wait(3))
                response = self.update(target, scope=target["scope"] | {"excluded_paths": ["/private"]})
                self.assertEqual(response.status_code, 200, response.text)
                with self.sessions() as db:
                    row = db.get(Assessment, assessment["id"])
                    self.assertEqual(row.status, "cancelling")
                    self.assertTrue(row.cancel_requested)
            finally:
                release.set()
                thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(observed, [(target["scope"], target["url"], True)])
        stopped = self.client.get(f"/api/v1/assessments/{assessment['id']}").json()
        self.assertEqual(stopped["status"], "cancelled")
        self.assertEqual(stopped["scope_snapshot"], assessment["scope_snapshot"])

    def test_archived_project_rejects_approval_and_scope_edit(self):
        target, project = self.target(approve=False)
        self.assertEqual(
            self.client.patch(f"/api/v1/projects/{project['id']}", json={"archived": True}).status_code, 200
        )
        self.assertEqual(self.approve(target).status_code, 409)
        self.assertEqual(self.update(target).status_code, 409)
        stored = self.client.get(f"/api/v1/targets/{target['id']}").json()
        self.assertEqual(stored["scope_version"], 1)
        self.assertEqual(stored["verification_status"], "awaiting_authorization")

    def test_scope_change_after_collection_retains_facts_without_claiming_remediation(self):
        target, _ = self.target()
        baseline = self.launch(target)
        self.assertTrue(run_one(self.sessions))
        self.server.secure_headers = True
        retest = self.launch(target, baseline["id"])

        def collect_then_revise(scope, url, cancelled, emit, *, request_starts=None):
            result = controlled_scan(scope, url, cancelled, emit, request_starts=request_starts)
            self.assertEqual(result["outcome"], "completed")
            self.assertGreater(len(result["observations"]), 0)
            self.assertEqual(result["findings"], [])
            revised = self.update(target, scope=target["scope"] | {"excluded_paths": ["/private"]})
            self.assertEqual(revised.status_code, 200, revised.text)
            return result

        with patch("aegis.worker.scan", side_effect=collect_then_revise):
            self.assertTrue(run_one(self.sessions))
        stopped = self.client.get(f"/api/v1/assessments/{retest['id']}").json()
        self.assertEqual(stopped["status"], "cancelled")
        self.assertGreater(len(stopped["observations"]), 0)
        self.assertEqual(stopped["scope_snapshot"], retest["scope_snapshot"])
        self.assertTrue(
            all(f["status"] != "fixed" for f in self.client.get("/api/v1/findings").json()["items"])
        )

    def test_expired_scope_denial_is_audited_and_project_name_update_is_validated(self):
        target, project = self.target()
        with patch("packages.security_policies.datetime") as clock:
            clock.now.return_value = datetime.now(timezone.utc) + timedelta(hours=2)
            response = self.client.post(
                "/api/v1/assessments",
                json={
                    "target_id": target["id"],
                    "idempotency_key": "expired-launch",
                    "expected_scope_version": 1,
                },
            )
        self.assertEqual(response.status_code, 422, response.text)
        with self.sessions() as db:
            event = db.scalar(
                select(AuditEvent).where(
                    AuditEvent.action == "assessment.scope_rejected", AuditEvent.resource_id == target["id"]
                )
            )
            self.assertIn("expired", event.detail["reason"])
            self.assertEqual(event.detail["scope_version"], 1)
        self.assertEqual(self.client.get("/api/v1/assessments").json()["total"], 0)
        self.assertTrue(self.client.get("/api/v1/audit").json()["integrity_valid"])
        self.assertEqual(
            self.client.patch(f"/api/v1/projects/{project['id']}", json={"name": "   "}).status_code, 422
        )
        self.assertEqual(self.client.get(f"/api/v1/projects/{project['id']}").json()["name"], project["name"])
        renamed = self.client.patch(f"/api/v1/projects/{project['id']}", json={"name": "  Revised project  "})
        self.assertEqual(renamed.status_code, 200)
        self.assertEqual(renamed.json()["name"], "Revised project")

    def test_scope_edit_enforces_organization_role_and_csrf(self):
        target, _ = self.target()
        with self.sessions() as db:
            other = Organization(name="Other synthetic organization")
            db.add(other)
            db.flush()
            add_user(db, "otherowner", workflow.PASSWORD, other.id, "owner")
            add_user(db, "localanalyst", workflow.PASSWORD, self.org_id, "analyst")
            # Grant the analyst project membership so RBAC allows reads; the scope edit is still
            # denied by role (CONTROL_ROLES only), not by membership.
            analyst_id = db.scalar(select(User.id).where(User.username == "localanalyst"))
            proj_id = db.scalar(select(Target.project_id).where(Target.id == target["id"]))
            db.add(ProjectMember(project_id=proj_id, user_id=analyst_id))
            db.commit()
        for username, expected in (("otherowner", 404), ("localanalyst", 403)):
            with TestClient(
                self.app, base_url=self.settings.origin, headers={"origin": self.settings.origin}
            ) as client:
                self.login(client, username)
                self.assertEqual(
                    client.get(f"/api/v1/targets/{target['id']}").status_code, 404 if expected == 404 else 200
                )
                response = client.patch(
                    f"/api/v1/targets/{target['id']}/scope",
                    json={"url": target["url"], "scope": target["scope"], "expected_scope_version": 1},
                )
                self.assertEqual(response.status_code, expected)
                self.assertEqual(
                    client.post(
                        f"/api/v1/targets/{target['id']}/approve",
                        json={
                            "acknowledgement": "I authorize this controlled laboratory target",
                            "expected_scope_version": 1,
                        },
                    ).status_code,
                    expected,
                )
        self.client.headers.pop("x-csrf-token")
        self.assertEqual(self.update(target).status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/targets/{target['id']}").json()["scope_version"], 1)
