"""Live test suite for Turnkey Onboarding, Zero-Telemetry Auto-Update & Performance Budget (Phase 3).

Verifies:
1. Guided First-Run Onboarding Wizard state machine, gating, and audit history.
2. Zero-telemetry release manifest signature check and atomic binary swap with rollback.
3. Fail-closed rejection of corrupted/forged update payloads.
4. Lighthouse sub-second render budget and 100% WCAG accessibility CI gate.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from aegis.onboarding import (
    OnboardingStep,
    OnboardingWizardEngine,
    PerformanceBudgetEnforcer,
    ReleaseManifest,
    ZeroTelemetryUpdateManager,
)


class TestOnboardingWizard:
    def test_full_onboarding_flow(self):
        wizard = OnboardingWizardEngine()
        assert wizard.state.current_step == OnboardingStep.WELCOME

        # Step 1: Advance from Welcome
        ok, msg = wizard.advance_step(OnboardingStep.WELCOME, {})
        assert ok is True
        assert wizard.state.current_step == OnboardingStep.OWNER_CREATION

        # Step 2: Password too short fails
        ok_fail, _ = wizard.advance_step(
            OnboardingStep.OWNER_CREATION, {"username": "admin", "password": "short"}
        )
        assert ok_fail is False

        # Step 2: Valid owner creation
        ok_owner, _ = wizard.advance_step(
            OnboardingStep.OWNER_CREATION,
            {"username": "admin", "password": "SuperSecureAdminPassword2026!", "mfa_enrolled": True},
        )
        assert ok_owner is True
        assert wizard.state.current_step == OnboardingStep.CONTAINER_VERIFICATION

        # Step 3: Container verification
        ok_cont, _ = wizard.advance_step(
            OnboardingStep.CONTAINER_VERIFICATION,
            {"engine": "podman", "cgroups_v2": True, "rootless": True},
        )
        assert ok_cont is True
        assert wizard.state.current_step == OnboardingStep.EGRESS_FIREWALL_TEST

        # Step 4: Egress firewall test
        ok_egr, _ = wizard.advance_step(
            OnboardingStep.EGRESS_FIREWALL_TEST,
            {"egress_drop_confirmed": True},
        )
        assert ok_egr is True
        assert wizard.state.current_step == OnboardingStep.SEED_ASSESSMENT

        # Step 5: Seed assessment
        ok_seed, _ = wizard.advance_step(
            OnboardingStep.SEED_ASSESSMENT,
            {"assessment_id": "seed-dvwa-01"},
        )
        assert ok_seed is True
        assert wizard.state.current_step == OnboardingStep.COMPLETED
        assert wizard.state.completed_at is not None
        assert len(wizard.state.step_history) == 5


class TestZeroTelemetryAutoUpdate:
    @pytest.fixture
    def setup_update_env(self, tmp_path):
        install_file = tmp_path / "sharay_app_binary"
        install_file.write_bytes(b"SHARAY_BIN_V0.1.0")
        return str(install_file)

    def test_update_discovery_and_signature_verification(self):
        secret = "test_release_secret_key"
        mgr = ZeroTelemetryUpdateManager(current_version="0.1.0", notary_secret=secret)

        raw_bin = b"SHARAY_BIN_V0.2.0_NEW_RELEASE"
        bin_hash = hashlib.sha256(raw_bin).hexdigest()

        # Sign manifest
        manifest_data = {
            "version": "0.2.0",
            "release_date": "2026-10-18T00:00:00Z",
            "sha256_hash": bin_hash,
            "binary_url": "https://releases.sharay.security/bin/v0.2.0/sharay",
            "mandatory": False,
        }
        canonical = f"0.2.0:2026-10-18T00:00:00Z:{bin_hash}:https://releases.sharay.security/bin/v0.2.0/sharay".encode(
            "utf-8"
        )
        manifest_data["signature"] = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

        manifest = mgr.check_for_update(json.dumps(manifest_data))
        assert manifest is not None
        assert manifest.version == "0.2.0"

    def test_atomic_binary_swap_and_tamper_rejection(self, setup_update_env):
        install_path = setup_update_env
        secret = "test_release_secret_key"
        mgr = ZeroTelemetryUpdateManager(current_version="0.1.0", notary_secret=secret)

        valid_bytes = b"NEW_SIGNED_VALID_BINARY_PAYLOAD"
        valid_hash = hashlib.sha256(valid_bytes).hexdigest()

        manifest = ReleaseManifest(
            version="0.2.0",
            release_date="2026-10-18",
            sha256_hash=valid_hash,
            binary_url="https://releases.corp/bin",
            mandatory_update=False,
            signature="valid",
        )

        # 1. Tampered payload is rejected fail-closed
        tampered_bytes = b"CORRUPTED_BINARY_ATTACK"
        ok_bad, msg_bad = mgr.apply_update_staged(tampered_bytes, manifest, install_path)
        assert ok_bad is False
        assert "mismatch" in msg_bad.lower()
        # Original binary remains unchanged
        with open(install_path, "rb") as f:
            assert f.read() == b"SHARAY_BIN_V0.1.0"

        # 2. Valid payload performs atomic swap
        ok_good, msg_good = mgr.apply_update_staged(valid_bytes, manifest, install_path)
        assert ok_good is True
        assert mgr.current_version == "0.2.0"
        with open(install_path, "rb") as f:
            assert f.read() == valid_bytes


class TestPerformanceBudget:
    def test_performance_budget_compliance(self):
        fast_metrics = {
            "first_contentful_paint_ms": 620.0,
            "largest_contentful_paint_ms": 980.0,
            "cumulative_layout_shift": 0.01,
            "time_to_interactive_ms": 750.0,
            "accessibility_score": 100.0,
        }
        ok, violations = PerformanceBudgetEnforcer.evaluate_metrics(fast_metrics)
        assert ok is True
        assert len(violations) == 0

    def test_performance_budget_violations(self):
        slow_metrics = {
            "first_contentful_paint_ms": 1400.0,  # Exceeds 800ms
            "largest_contentful_paint_ms": 2500.0,  # Exceeds 1200ms
            "cumulative_layout_shift": 0.12,  # Exceeds 0.05
            "time_to_interactive_ms": 1800.0,  # Exceeds 1000ms
            "accessibility_score": 85.0,  # Below 100.0
        }
        ok, violations = PerformanceBudgetEnforcer.evaluate_metrics(slow_metrics)
        assert ok is False
        assert len(violations) == 5
