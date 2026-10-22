"""Regressions for the single execution authorization & budget contract (roadmap P0-A).

Each test pins a reproduced audit counterexample so it can never silently return.
"""

import unittest
from datetime import UTC, datetime, timedelta

from aegis.schemas import ScanConfig
from packages.security_policies import ScopePolicy


def _scope(request_rate: float = 1.0) -> ScopePolicy:
    now = datetime.now(UTC)
    return ScopePolicy(
        hosts=["example.com"],
        allowed_origins=["https://example.com"],
        allowed_paths=["/"],
        request_rate=request_rate,
        max_concurrency=1,
        starts_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1),
    )


class RateCeilingTests(unittest.TestCase):
    """E03: a requested rate must never raise the effective rate above the approved ceiling."""

    def test_requested_rate_cannot_exceed_approved(self):
        scope = _scope(request_rate=1.0)
        self.assertEqual(ScanConfig(rate=150).within_scope(scope).rate, 1.0)
        self.assertEqual(ScanConfig(rate=5000).within_scope(scope).rate, 1.0)

    def test_absent_requested_rate_uses_the_approved_rate(self):
        self.assertEqual(ScanConfig().within_scope(_scope(request_rate=3.0)).rate, 3.0)

    def test_a_lower_requested_rate_is_honoured(self):
        self.assertEqual(ScanConfig(rate=2).within_scope(_scope(request_rate=5.0)).rate, 2.0)

    def test_effective_rate_never_exceeds_approved_across_a_sweep(self):
        for approved in (1.0, 2.5, 10.0, 50.0):
            scope = _scope(request_rate=approved)
            for requested in (None, 1, approved, approved + 1, 5000):
                effective = ScanConfig(rate=requested).within_scope(scope).rate
                self.assertLessEqual(effective, approved, (approved, requested))
                self.assertGreater(effective, 0)


if __name__ == "__main__":
    unittest.main()
