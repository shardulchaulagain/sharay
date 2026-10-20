"""Acceptance & Integration Tests for Turnkey Onboarding, Probes & Scanner Plugin SDK.

Verifies:
1. Server-side container and egress firewall probes in aegis/onboarding.py.
2. Per-session / per-installation onboarding state isolation (no shared mutable global singleton).
3. ScannerAdapterRegistry dynamic plugin management and reference SecurityHeadersScannerAdapter execution.
"""

from __future__ import annotations

import unittest

from aegis.onboarding import (
    BaseScannerAdapter,
    OnboardingStep,
    OnboardingWizardEngine,
    ScannerAdapterRegistry,
    SecurityHeadersScannerAdapter,
    default_scanner_registry,
    get_onboarding_wizard,
    probe_container_runtime,
    probe_egress_firewall,
)


class TestOnboardingAndPluginSDK(unittest.TestCase):
    def test_server_side_container_probe(self):
        res = probe_container_runtime()
        self.assertIsInstance(res, dict)
        self.assertIn("verified", res)
        if res["verified"]:
            self.assertIn(res["engine"], ("podman", "docker"))
            self.assertTrue(res["rootless"])
            self.assertTrue(res["cgroups_v2"])
        else:
            self.assertIn("reason", res)

    def test_server_side_egress_firewall_probe(self):
        res = probe_egress_firewall()
        self.assertIsInstance(res, dict)
        self.assertTrue(res["verified"])
        self.assertGreater(res["v4_rules_count"], 0)
        self.assertGreater(res["nftables_rules_count"], 0)
        self.assertTrue(res["attestation_id"].startswith("attest-"))
        self.assertEqual(len(res["attestation_signature"]), 128)  # Ed25519 signature

    def test_per_session_isolation(self):
        session_a = get_onboarding_wizard("tenant-alpha")
        session_b = get_onboarding_wizard("tenant-beta")

        # Advance Session A
        session_a.advance_step(OnboardingStep.WELCOME, {})
        session_a.advance_step(
            OnboardingStep.OWNER_CREATION,
            {"username": "alpha_admin", "password": "StrongPasswordAlpha123!"},
        )

        # Assert Session B is completely unaffected
        self.assertEqual(session_a.state.current_step, OnboardingStep.CONTAINER_VERIFICATION)
        self.assertEqual(session_a.state.owner_username, "alpha_admin")
        self.assertEqual(session_b.state.current_step, OnboardingStep.WELCOME)
        self.assertIsNone(session_b.state.owner_username)

    def test_onboarding_wizard_with_real_probes(self):
        wizard = OnboardingWizardEngine(session_id="test_run")
        self.assertEqual(wizard.state.current_step, OnboardingStep.WELCOME)

        # 1. Welcome
        ok, _ = wizard.advance_step(OnboardingStep.WELCOME, {})
        self.assertTrue(ok)
        self.assertEqual(wizard.state.current_step, OnboardingStep.OWNER_CREATION)

        # 2. Owner Creation
        ok, _ = wizard.advance_step(
            OnboardingStep.OWNER_CREATION,
            {"username": "shardul", "password": "SecureEnterprisePassword2026!"},
        )
        self.assertTrue(ok)
        self.assertEqual(wizard.state.current_step, OnboardingStep.CONTAINER_VERIFICATION)

        # 3. Container Verification via real probe or dry_run fallback
        probe_res = probe_container_runtime()
        if probe_res["verified"]:
            ok, _ = wizard.advance_step(
                OnboardingStep.CONTAINER_VERIFICATION,
                {"probe_result": probe_res},
            )
            self.assertTrue(ok)
            self.assertTrue(wizard.state.container_verified)
        else:
            # If host doesn't have container engine, test graceful dry_run mode
            ok, _ = wizard.advance_step(
                OnboardingStep.CONTAINER_VERIFICATION,
                {"dry_run": True},
            )
            self.assertTrue(ok)
            self.assertFalse(wizard.state.container_verified)

        self.assertEqual(wizard.state.current_step, OnboardingStep.EGRESS_FIREWALL_TEST)

        # 4. Egress Firewall Test via real probe
        egress_probe = probe_egress_firewall()
        ok, msg = wizard.advance_step(
            OnboardingStep.EGRESS_FIREWALL_TEST,
            {"probe_result": egress_probe},
        )
        self.assertTrue(ok)
        self.assertTrue(wizard.state.egress_verified)
        self.assertEqual(wizard.state.current_step, OnboardingStep.SEED_ASSESSMENT)

        # 5. Seed Assessment
        ok, _ = wizard.advance_step(
            OnboardingStep.SEED_ASSESSMENT,
            {"assessment_id": "seed-assessment-101"},
        )
        self.assertTrue(ok)
        self.assertEqual(wizard.state.current_step, OnboardingStep.COMPLETED)
        self.assertIsNotNone(wizard.state.completed_at)

    def test_scanner_adapter_plugin_sdk(self):
        registry = ScannerAdapterRegistry()

        class CustomJWTAdapter(BaseScannerAdapter):
            def name(self) -> str:
                return "custom_jwt_checker"

            def version(self) -> str:
                return "2.1.0"

            def supported_vuln_classes(self) -> list[str]:
                return ["jwt_alg_none", "jwt_weak_hmac"]

            def run_check(self, target_origin: str, endpoint: str, parameters: list[str]) -> list[dict]:
                return [
                    {
                        "vuln_class": "jwt_alg_none",
                        "target": f"{target_origin}{endpoint}",
                        "impact": "authentication_bypass",
                    }
                ]

        adapter = CustomJWTAdapter()
        registry.register(adapter)

        self.assertIsNotNone(registry.get("custom_jwt_checker"))
        all_adapters = registry.list_all()
        self.assertEqual(len(all_adapters), 1)
        self.assertEqual(all_adapters[0]["name"], "custom_jwt_checker")

        # Execute check through adapter
        findings = adapter.run_check("https://target.corp", "/api/v1/auth", ["token"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vuln_class"], "jwt_alg_none")

        # Unregister
        registry.unregister("custom_jwt_checker")
        self.assertIsNone(registry.get("custom_jwt_checker"))

    def test_default_registry_has_reference_adapter(self):
        ref = default_scanner_registry.get("security_headers_native")
        self.assertIsNotNone(ref)
        self.assertIsInstance(ref, SecurityHeadersScannerAdapter)
        findings = ref.run_check("https://api.example.com", "/health", [])
        self.assertGreater(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
