"""Sector O9: large-surface scale -- route-template dedup, prioritization, discovery ingestion,
adaptive rate control, and resumable crawl state.
"""

from __future__ import annotations

import unittest

from packages.scanner_adapters.integrations import surface as s


class SurfaceScaleTest(unittest.TestCase):
    def test_route_template_dedup_collapses_big_surface(self):
        urls = [f"http://t/user/{i}/profile" for i in range(1, 500)]
        urls += ["http://t/user/abc12345-0000-0000-0000-000000000000/profile"]  # uuid -> same template
        urls += ["http://t/admin", "http://t/product-999999"]
        deduped = s.dedupe_route_templates(urls)
        self.assertLessEqual(len(deduped), 3, "all /user/{id}/profile should collapse to one template")

    def test_prioritization_ranks_high_value_first(self):
        urls = [
            "http://t/static/logo.png",
            "http://t/about",
            "http://t/api/orders?id=1",
            "http://t/admin/login",
            "http://t/upload",
        ]
        ranked = s.prioritize_surface(urls)
        # The highest-value endpoint (API with id param) ranks first; the static asset sinks to the
        # bottom tier (behind every parameterized/admin/upload endpoint).
        self.assertEqual(ranked[0], "http://t/api/orders?id=1")
        self.assertIn("http://t/static/logo.png", ranked[-2:])
        self.assertLess(ranked.index("http://t/admin/login"), ranked.index("http://t/static/logo.png"))

    def test_sitemap_and_robots_ingestion(self):
        locs = s.parse_sitemap(
            b"<urlset><url><loc>http://t/a</loc></url><url><loc>http://t/b</loc></url></urlset>"
        )
        self.assertEqual(locs, ["http://t/a", "http://t/b"])
        robots = s.parse_robots(
            b"User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: http://t/sitemap.xml"
        )
        self.assertIn("/admin", robots["disallow"])
        self.assertIn("/public", robots["allow"])
        self.assertIn("http://t/sitemap.xml", robots["sitemaps"])

    def test_adaptive_rate_control_backoff_and_speedup(self):
        r = s.AdaptiveRateController(base_interval=0.1)
        before = r.interval
        self.assertGreater(r.observe(429), before)  # throttled -> back off
        self.assertGreater(r.observe(503), before)
        high = r.interval
        for _ in range(5):
            r.observe(200)  # sustained success -> speed up
        self.assertLess(r.interval, high)

    def test_resumable_state_round_trip(self):
        st = s.ResumableSurfaceState()
        for u in ("http://t/a", "http://t/b", "http://t/c"):
            st.add(u)
        batch = st.next_batch(2)
        self.assertEqual(batch, ["http://t/a", "http://t/b"])
        restored = s.ResumableSurfaceState.from_dict(st.to_dict())
        self.assertEqual(restored.pending, ["http://t/c"])
        # A visited route template is not re-queued on resume.
        restored.add("http://t/a")
        self.assertNotIn("http://t/a", restored.pending)


if __name__ == "__main__":
    unittest.main()
