"""Unit and integration test suite for Sector 7: TOTP MFA & External Audit Notarization.

Proves:
1. RFC 6238 TOTP generation, URI formatting, and validation.
2. Clock drift window tolerance (+/- 30s) and replay rejection.
3. Backup recovery codes single-use redemption.
4. External audit chain notarization, cryptographic receipt verification, and tamper detection.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from aegis.audit import AuditNotaryService, audit, verify_audit
from aegis.auth import TOTPEngine
from aegis.models import AuditEvent, Base, Organization


@pytest.fixture
def audit_db():
    folder = tempfile.TemporaryDirectory(prefix="test-notary-")
    db_path = Path(folder.name) / "test.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def setup_sqlite(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(engine, expire_on_commit=False)

    with session_factory() as db:
        org = Organization(id="org-notary-1", name="Audit Notary Org")
        db.add(org)
        db.commit()

    yield engine, session_factory
    engine.dispose()
    folder.cleanup()


def test_totp_rfc6238_generation_and_verification():
    """Verify standard TOTP generation and verification."""
    secret = TOTPEngine.generate_secret()
    assert len(secret) >= 26

    uri = TOTPEngine.generate_provisioning_uri(secret, "admin@corp.io", issuer="SHARAY")
    assert uri.startswith("otpauth://totp/SHARAY%3Aadmin%40corp.io")
    assert f"secret={secret}" in uri

    fixed_time = 1700000000.0
    code = TOTPEngine.generate_otp(secret, timestamp=fixed_time)
    assert len(code) == 6
    assert code.isdigit()

    # Exact match succeeds
    valid, counter = TOTPEngine.verify_otp(secret, code, timestamp=fixed_time)
    assert valid is True
    assert counter == int(fixed_time // 30)

    # Invalid code rejected
    invalid_code = "000000" if code != "000000" else "999999"
    valid, _ = TOTPEngine.verify_otp(secret, invalid_code, timestamp=fixed_time)
    assert valid is False


def test_totp_drift_window_and_replay_prevention():
    """Verify tolerance for clock skew and replay attacks."""
    secret = TOTPEngine.generate_secret()
    base_time = 1700000000.0
    used_counters = set()

    # Generate OTP at t=base_time
    code = TOTPEngine.generate_otp(secret, timestamp=base_time)

    # Verify at t=base_time + 25s (within drift window)
    valid, c1 = TOTPEngine.verify_otp(secret, code, timestamp=base_time + 25.0, used_counters=used_counters)
    assert valid is True
    assert c1 is not None

    # Replay of the exact same counter must be rejected
    valid, c2 = TOTPEngine.verify_otp(secret, code, timestamp=base_time + 25.0, used_counters=used_counters)
    assert valid is False
    assert c2 is None

    # Step beyond allowed window (+90s = 3 steps) fails
    code_skewed = TOTPEngine.generate_otp(secret, timestamp=base_time + 90.0)
    valid, _ = TOTPEngine.verify_otp(secret, code_skewed, timestamp=base_time, allowed_drift_windows=1)
    assert valid is False


def test_backup_recovery_codes():
    """Verify single-use backup recovery codes."""
    plain, hashed = TOTPEngine.generate_backup_codes(count=5)
    assert len(plain) == 5
    assert len(hashed) == 5

    # First redemption succeeds
    first_code = plain[0]
    assert TOTPEngine.redeem_backup_code(first_code, hashed) is True
    assert len(hashed) == 4

    # Second redemption of same code fails
    assert TOTPEngine.redeem_backup_code(first_code, hashed) is False

    # Bogus code fails
    assert TOTPEngine.redeem_backup_code("XXXX-YYYY", hashed) is False


def test_external_audit_notarization_and_tamper_detection(audit_db):
    """Verify cryptographic notarization anchors and fail-closed tamper detection."""
    engine, session_factory = audit_db
    notary = AuditNotaryService()

    with session_factory() as db:
        # Create audit chain
        for i in range(5):
            audit(
                db,
                org="org-notary-1",
                actor="operator-1",
                action="scope.update",
                resource=f"res-{i}",
                detail={"step": i},
            )
        db.commit()
        assert verify_audit(db) is True

        # Notarize chain tip
        receipt = notary.notarize_chain(db, organization_id="org-notary-1")
        assert receipt is not None
        assert receipt.last_event_id == 5
        assert len(receipt.chain_tip_hash) == 64
        assert len(receipt.notary_signature) == 64

        # Verification against unmodified DB succeeds
        valid, msg = notary.verify_chain_against_receipt(db, receipt)
        assert valid is True
        assert "verified" in msg

    # Adversarial test: Tamper with event #3 in the database directly
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE audit_events SET detail = :tampered WHERE id = 3"),
            {"tampered": '{"step": 999}'},
        )
        conn.commit()

    # Re-verify with tampered record: audit ledger verification must detect alteration
    with session_factory() as db:
        # 1. Internal verify_audit must fail
        assert verify_audit(db) is False

        # 2. Even if an attacker recomputed hashes for 3, 4, 5, the external notary anchor
        # retains the original signed tip, so verification against notary receipt fails
        event_5 = db.get(AuditEvent, 5)
        # Manually tamper event 5 to test notary tip mismatch
        event_5.event_hash = "0" * 64
        db.commit()

        valid, err_msg = notary.verify_chain_against_receipt(db, receipt)
        assert valid is False
        assert "Tamper detected" in err_msg
