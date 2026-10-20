"""Product API tests for Turnkey Onboarding Wizard and Zero-Telemetry Auto-Update (Sector 11)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from aegis.api import create_app
from aegis.auth import provision_owner
from aegis.config import Settings
from aegis.onboarding import OnboardingStep, onboarding_wizard

PASSWORD = "Synthetic-test-password-761!"


class TestOnboardingApi(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.settings = Settings(Path(self.folder.name), start_worker=False)
        self.app = create_app(self.settings)
        self.sessions = self.app.state.sessions

        with self.sessions() as db:
            self.owner = provision_owner(db, "testowner", PASSWORD)
            self.org_id = self.owner.organization_id
            db.commit()

        self.client = TestClient(self.app, base_url=self.settings.origin)
        self.client.headers["origin"] = self.settings.origin

        # Sign in as owner
        res = self.client.post("/api/v1/auth/login", json={"username": "testowner", "password": PASSWORD})
        self.assertEqual(res.status_code, 200)
        self.client.headers["x-csrf-token"] = res.json()["csrf_token"]

        # Reset wizard state for test isolation
        onboarding_wizard.state.current_step = OnboardingStep.WELCOME
        onboarding_wizard.state.step_history.clear()

    def tearDown(self):
        self.folder.cleanup()

    def test_onboarding_state_and_advance_endpoints(self):
        # 1. Query initial state
        res = self.client.get("/api/v1/onboarding/state")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["current_step"], "WELCOME")

        # 2. Advance to OWNER_CREATION
        res_adv = self.client.post(
            "/api/v1/onboarding/advance",
            json={"step": "WELCOME", "data": {}},
        )
        self.assertEqual(res_adv.status_code, 200)
        self.assertEqual(res_adv.json()["current_step"], "OWNER_CREATION")

        # 3. Advance to CONTAINER_VERIFICATION with owner account
        res_owner = self.client.post(
            "/api/v1/onboarding/advance",
            json={
                "step": "OWNER_CREATION",
                "data": {
                    "username": "admin",
                    "password": "SuperSecureAdminPassword2026!",
                    "mfa_enrolled": True,
                },
            },
        )
        self.assertEqual(res_owner.status_code, 200)
        self.assertEqual(res_owner.json()["current_step"], "CONTAINER_VERIFICATION")

    def test_system_update_check_and_apply_endpoints(self):
        secret = "sharay_release_secret_2026"
        dummy_bin = b"SHARAY_UPDATED_BINARY_CORE_2026"
        bin_hash = hashlib.sha256(dummy_bin).hexdigest()

        manifest_dict = {
            "version": "1.5.0",
            "release_date": "2026-10-18T20:00:00Z",
            "sha256_hash": bin_hash,
            "binary_url": "https://releases.sharay.security/bin/v1.5.0/sharay",
            "mandatory": False,
        }
        canonical = f"1.5.0:2026-10-18T20:00:00Z:{bin_hash}:https://releases.sharay.security/bin/v1.5.0/sharay".encode(
            "utf-8"
        )
        sig = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        manifest_dict["signature"] = sig

        # Check for update
        res_check = self.client.post(
            "/api/v1/system/update/check",
            json={"manifest_json": json.dumps(manifest_dict)},
        )
        self.assertEqual(res_check.status_code, 200)
        check_data = res_check.json()
        self.assertTrue(check_data["has_update"])
        self.assertEqual(check_data["manifest"]["version"], "1.5.0")

        # Apply update
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            target_path = tf.name
            tf.write(b"ORIGINAL_OLD_BINARY")

        try:
            b64_payload = base64.b64encode(dummy_bin).decode("ascii")
            res_apply = self.client.post(
                "/api/v1/system/update/apply",
                json={
                    "binary_bytes_b64": b64_payload,
                    "manifest": manifest_dict,
                    "target_install_path": target_path,
                },
            )
            self.assertEqual(res_apply.status_code, 200)
            self.assertTrue(res_apply.json()["success"])
            self.assertEqual(res_apply.json()["version"], "1.5.0")

            # Verify file was updated on disk
            with open(target_path, "rb") as f:
                self.assertEqual(f.read(), dummy_bin)
        finally:
            Path(target_path).unlink(missing_ok=True)
            Path(f"{target_path}.bak").unlink(missing_ok=True)
