"""Acceptance & Integration Tests for Asymmetric Cryptographic Signatures.

Verifies Sector 7 & Sector 11 requirements:
1. RFC 8032 Ed25519 asymmetric signatures in packages/crypto/ed25519.py.
2. Cross-platform installer package & manifest signing in packages/packaging.py.
3. Zero-telemetry auto-update manifest verification in services/update_worker/updater.py.
4. Egress attestation log signing with Ed25519 in services/scanner_worker/container.py.
"""

from __future__ import annotations

import json
import unittest

from packages.crypto.ed25519 import (
    ed25519_publickey,
    ed25519_sign,
    ed25519_sign_hex,
    ed25519_verify,
    ed25519_verify_hex,
    generate_keypair,
)
from packages.packaging import (
    InstallerSignatureEngine,
)
from packages.packaging import (
    ReleaseManifest as PackagingReleaseManifest,
)
from services.scanner_worker.container import EgressAttestationLogger
from services.update_worker.updater import (
    ZeroTelemetryUpdateManager,
)


class TestAsymmetricSignatures(unittest.TestCase):
    def test_ed25519_core_signing_and_verification(self):
        sk, pk = generate_keypair()
        self.assertEqual(len(sk), 32)
        self.assertEqual(len(pk), 32)

        # Derived public key matches
        self.assertEqual(ed25519_publickey(sk), pk)

        msg = b"SHARAY-RELEASE-MANIFEST-v1.0.0-HASH"
        sig = ed25519_sign(msg, sk, pk)
        self.assertEqual(len(sig), 64)

        # Valid signature verifies
        self.assertTrue(ed25519_verify(sig, msg, pk))

        # Tampered message fails
        self.assertFalse(ed25519_verify(sig, b"TAMPERED-MESSAGE", pk))

        # Wrong public key fails
        _, wrong_pk = generate_keypair()
        self.assertFalse(ed25519_verify(sig, msg, wrong_pk))

        # Hex helpers
        sk_hex = sk.hex()
        pk_hex = pk.hex()
        sig_hex = ed25519_sign_hex(msg, sk_hex)
        self.assertTrue(ed25519_verify_hex(sig_hex, msg, pk_hex))
        self.assertFalse(ed25519_verify_hex(sig_hex, msg, wrong_pk.hex()))

    def test_packaging_installer_signature_engine(self):
        sk, pk = generate_keypair()

        # Engine configured with private signing key (used by build server)
        server_engine = InstallerSignatureEngine(signing_key=sk)
        self.assertEqual(server_engine.public_key, pk)

        pkg_bytes = b"BINARY_BYTES_FOR_MACOS_DMG_INSTALLER"
        artifact = server_engine.sign_artifact(pkg_bytes, "darwin-arm64", "dmg", "sharay-mac.dmg")
        self.assertEqual(len(artifact.signature), 128)  # 64 bytes in hex

        manifest = server_engine.generate_manifest("1.0.0", [artifact], channel="stable")
        self.assertEqual(len(manifest.manifest_signature), 128)

        # Client engine configured with ONLY public key (distributed to users)
        client_engine = InstallerSignatureEngine(public_key=pk)
        self.assertIsNone(client_engine.signing_key)
        self.assertEqual(client_engine.public_key_hex, pk.hex())

        # Client verifies successfully without holding the secret signing key
        verified, msg = client_engine.verify_manifest(manifest)
        self.assertTrue(verified)
        self.assertIn("verified successfully", msg)

        # Client cannot sign (raises error)
        with self.assertRaises(ValueError):
            client_engine.sign_artifact(b"data", "linux-x86_64", "deb", "sharay.deb")

        # Forged manifest fails verification
        forged_manifest = PackagingReleaseManifest(
            version="1.0.0",
            channel="stable",
            published_at=manifest.published_at,
            artifacts=manifest.artifacts,
            manifest_signature="a" * 128,
        )
        forged_verified, _ = client_engine.verify_manifest(forged_manifest)
        self.assertFalse(forged_verified)

    def test_update_manager_asymmetric_verification(self):
        sk, pk = generate_keypair()
        sk_hex = sk.hex()
        pk_hex = pk.hex()

        manifest_data = {
            "version": "1.2.0",
            "release_date": "2026-10-19",
            "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "binary_url": "https://releases.sharay.invalid/v1.2.0/sharay",
            "mandatory": True,
        }

        # Server signs manifest with private key
        sig_hex = ZeroTelemetryUpdateManager.sign_manifest_ed25519(manifest_data, sk_hex)
        manifest_data["signature"] = sig_hex

        # Client update manager holds ONLY public key
        client_mgr = ZeroTelemetryUpdateManager(current_version="1.1.0", public_key_hex=pk_hex)
        update = client_mgr.check_for_update(json.dumps(manifest_data))
        self.assertIsNotNone(update)
        self.assertEqual(update.version, "1.2.0")

        # Tampered manifest is rejected
        tampered_data = dict(manifest_data)
        tampered_data["sha256_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
        self.assertIsNone(client_mgr.check_for_update(json.dumps(tampered_data)))

    def test_egress_attestation_asymmetric_signing(self):
        logger = EgressAttestationLogger()
        self.assertTrue(logger.is_asymmetric)
        self.assertIsNotNone(logger.public_key)

        rules = [["iptables", "-A", "EGRESS", "-d", "93.184.216.34", "-j", "ACCEPT"]]
        receipt = logger.record_ruleset_applied("assessment-corp-99", "example.com", rules)

        self.assertEqual(len(receipt.signature_sha256), 128)
        self.assertTrue(logger.verify_receipt(receipt))

        # External party verifies with only the public key
        external_pk = receipt.public_key_hex
        self.assertTrue(logger.verify_receipt(receipt, public_key_hex=external_pk))

        # Teardown attestation
        td_receipt = logger.record_ruleset_teardown(receipt.attestation_id, clean=True)
        self.assertEqual(td_receipt.state, "TORN_DOWN")
        self.assertTrue(logger.verify_receipt(td_receipt, public_key_hex=external_pk))


if __name__ == "__main__":
    unittest.main()
