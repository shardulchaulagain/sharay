"""Sector O4 acceptance: response-driven adaptive firing changes the outcome.

Against a WAF that blocks raw payloads, the adaptive evaluator learns the block, routes around
it, and confirms the vulnerability; the non-adaptive evaluator confirms nothing on the same WAF.
This is the difference between static firing and variable, response-driven methodology.
"""

from __future__ import annotations

import unittest
import urllib.parse

from packages.offensive_capability import AdaptivePayloadEvaluator, PayloadForgeEvaluator
from packages.scanner_adapters.reproducer import DeterministicReproducer


def _naive_space_waf(url, timeout=8.0, headers=None, method="GET", data=None):
    """Blocks payloads that carry a raw space + injection marker (403); /**/-fragmented bypasses.

    The vulnerable response carries a signature the differential oracle recognizes ('sql syntax').
    """
    dec = urllib.parse.unquote_plus(url)
    qs = dec.split("?", 1)[-1]
    marker = ("'" in dec) or ("UNION" in dec.upper()) or ("SLEEP" in dec.upper())
    if marker and " " in qs:
        return 403, b"request blocked by waf keyword filter", 10.0
    if marker:
        return 200, b"You have an error in your SQL syntax; check the manual near 1", 10.0
    return 200, b"catalog item listing normal page here", 10.0


class AdaptiveFiringTest(unittest.TestCase):
    def test_adaptation_defeats_waf_that_non_adaptive_cannot(self):
        adaptive = AdaptivePayloadEvaluator(reproducer=DeterministicReproducer(http_client=_naive_space_waf))
        res = adaptive.evaluate_adaptive(
            base_url="http://127.0.0.1:9/item", fuzz_param="id", vuln_type="sqli", count=4
        )

        self.assertGreater(res["adaptations"], 0, "adaptive loop never routed around the WAF block")
        self.assertGreater(len(res["confirmed"]), 0, "adaptive firing confirmed nothing")
        bypassed = [c for c in res["confirmed"] if c["waf_bypassed"]]
        self.assertTrue(bypassed, "confirmations did not come from a WAF-bypassed payload")
        self.assertIn("/**/", bypassed[0]["payload"])  # the space->comment bypass is visible

        non_adaptive = PayloadForgeEvaluator(reproducer=DeterministicReproducer(http_client=_naive_space_waf))
        nv = non_adaptive.evaluate_payload_sequence(
            base_url="http://127.0.0.1:9/item", fuzz_param="id", vuln_type="sqli", count=4
        )
        self.assertEqual(len(nv), 0, "non-adaptive should be blocked by the WAF")
        # The whole point: adaptation turned zero confirmations into some.
        self.assertGreater(len(res["confirmed"]), len(nv))


if __name__ == "__main__":
    unittest.main()
