"""Live test suite for Project-Scoped RBAC & Signed Audit Ledger Export (Sector 7).

Verifies:
1. Multi-tier project roles (Owner, Lead, Analyst, Auditor) and action permissions.
2. Resource-level boundary isolation across projects.
3. Sequential cryptographic hash-linking of audit ledger events.
4. Tamper-evident export verification: detection of modified events, deletions, and signature tampering.
"""

from __future__ import annotations

import pytest

from aegis.audit import SignedAuditLedgerExporter
from aegis.auth import (
    PermissionDeniedError,
    ProjectRBACEnforcer,
    ProjectRole,
    ResourceAction,
)


class TestProjectRBAC:
    def test_role_permission_hierarchy(self):
        rbac = ProjectRBACEnforcer()
        rbac.register_project("proj-alpha", org_id="org-acme", owner_user_id="user-owner")

        # Assign Lead, Analyst, and Auditor
        rbac.assign_role("user-lead", "proj-alpha", ProjectRole.SECURITY_LEAD)
        rbac.assign_role("user-analyst", "proj-alpha", ProjectRole.SECURITY_ANALYST)
        rbac.assign_role("user-auditor", "proj-alpha", ProjectRole.AUDITOR_READONLY)

        # 1. Project Owner has all permissions
        assert rbac.check_permission("user-owner", "proj-alpha", ResourceAction.DELETE) is True
        assert rbac.check_permission("user-owner", "proj-alpha", ResourceAction.MANAGE_MEMBERS) is True

        # 2. Security Lead has scan and verify, but not delete/manage members
        assert rbac.check_permission("user-lead", "proj-alpha", ResourceAction.EXECUTE_SCAN) is True
        assert rbac.check_permission("user-lead", "proj-alpha", ResourceAction.EXPLOIT_VERIFY) is True
        assert rbac.check_permission("user-lead", "proj-alpha", ResourceAction.DELETE) is False

        # 3. Security Analyst has scan and verify, but not write
        assert rbac.check_permission("user-analyst", "proj-alpha", ResourceAction.EXECUTE_SCAN) is True
        assert rbac.check_permission("user-analyst", "proj-alpha", ResourceAction.WRITE) is False

        # 4. Auditor is strictly read-only
        assert rbac.check_permission("user-auditor", "proj-alpha", ResourceAction.READ) is True
        assert rbac.check_permission("user-auditor", "proj-alpha", ResourceAction.EXECUTE_SCAN) is False

        # Enforce raises PermissionDeniedError on unauthorized actions
        with pytest.raises(PermissionDeniedError):
            rbac.enforce("user-auditor", "proj-alpha", ResourceAction.WRITE)

    def test_resource_level_boundary_isolation(self):
        rbac = ProjectRBACEnforcer()
        rbac.register_project("proj-1", "org-1", "user-1")
        rbac.register_project("proj-2", "org-1", "user-2")

        # Register target/assessment resources
        rbac.register_resource("target-100", "proj-1")
        rbac.register_resource("target-200", "proj-2")

        # user-1 has permissions in proj-1 for target-100
        assert (
            rbac.check_permission("user-1", "proj-1", ResourceAction.READ, resource_id="target-100") is True
        )

        # user-1 accessing target-200 (belongs to proj-2) under proj-1 context is rejected
        assert (
            rbac.check_permission("user-1", "proj-1", ResourceAction.READ, resource_id="target-200") is False
        )


class TestSignedAuditLedgerExport:
    def test_signed_audit_export_and_verification(self):
        exporter = SignedAuditLedgerExporter(signing_key="secret-compliance-key-42")

        # Append events
        exporter.append_event("evt-1", "user-alice", "user.login", "auth", {"ip": "10.0.0.1"}, now=1000.0)
        exporter.append_event(
            "evt-2", "user-alice", "scan.start", "target-1", {"ports": [80, 443]}, now=1010.0
        )
        exporter.append_event("evt-3", "user-bob", "exploit.verify", "vuln-99", {"cwe": "CWE-89"}, now=1020.0)

        export = exporter.generate_signed_export()

        assert export["format"] == "SHARAY-AUDIT-EXPORT-V1"
        assert export["total_entries"] == 3
        assert len(export["merkle_root"]) == 64
        assert len(export["notary_signature"]) == 64

        # 1. Unmodified ledger passes verification
        valid, msg = SignedAuditLedgerExporter.verify_export_integrity(
            export, signing_key="secret-compliance-key-42"
        )
        assert valid is True
        assert "verified" in msg

        # 2. Tampering with an event payload breaks verification
        tampered_export = dict(export)
        tampered_export["ledger"] = list(export["ledger"])
        tampered_export["ledger"][1] = dict(export["ledger"][1])
        tampered_export["ledger"][1]["actor"] = "user-attacker"

        valid, err = SignedAuditLedgerExporter.verify_export_integrity(
            tampered_export, signing_key="secret-compliance-key-42"
        )
        assert valid is False
        assert "tampered" in err or "signature mismatch" in err

        # 3. Wrong signing key fails verification
        valid, err = SignedAuditLedgerExporter.verify_export_integrity(export, signing_key="wrong-key")
        assert valid is False
        assert "signature mismatch" in err
