"""Unit tests for the in-scope web crawler and HTML extractor."""

import unittest
from unittest.mock import MagicMock, patch

from packages.scanner_adapters import Destination, scan_live_nuclei
from packages.scanner_adapters.integrations import crawler as crawler_mod
from packages.scanner_adapters.integrations.crawler import (
    _HTMLStructureExtractor,
    _is_in_scope,
    crawl,
    parse_js_assets,
    parse_robots_txt,
    parse_sitemap_xml,
)


class JsAssetExtractionTests(unittest.TestCase):
    """P1.4: JS endpoint/param/secret mining."""

    def test_extracts_same_origin_endpoints_and_param_names(self):
        js = """
        const base = fetch("/api/v2/users?role=admin&active=1");
        axios.get('/internal/report');
        xhr.open("POST", `/orders/${id}/submit`);  // template literal -> skipped
        var ext = "https://evil.example.com/steal";  // cross-origin -> not a relative path
        """
        eps, params, secrets = parse_js_assets(js, "https://app.test")
        self.assertIn("/api/v2/users", eps)
        self.assertIn("/internal/report", eps)
        self.assertIn("role", params)
        self.assertIn("active", params)
        self.assertNotIn("https://evil.example.com/steal", eps)

    def test_extracts_and_redacts_secrets(self):
        js = 'const k = "AKIAIOSFODNN7EXAMPLE"; const api_key = "abcd1234efgh5678ijkl";'
        _, _, secrets = parse_js_assets(js, "https://app.test")
        types = {s["type"] for s in secrets}
        self.assertIn("aws_access_key", types)
        # the full secret value is never echoed back
        self.assertFalse(any("AKIAIOSFODNN7EXAMPLE" == s["match"] for s in secrets))

    def test_benign_js_yields_nothing(self):
        eps, params, secrets = parse_js_assets("function add(a,b){return a+b;}\nconsole.log('hi');", "https://app.test")
        self.assertEqual((eps, params, secrets), ([], [], []))


class CrawlerStructureTests(unittest.TestCase):
    def test_html_extractor_collects_links_forms_and_scripts(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <script src="/static/app.js"></script>
        </head>
        <body>
            <a href="/about">About Us</a>
            <a href="https://example.com/contact?source=web">Contact</a>
            <a href="https://other.com/external">External</a>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <input type="hidden" name="csrf_token" />
            </form>
        </body>
        </html>
        """
        extractor = _HTMLStructureExtractor("https://example.com/")
        extractor.feed(html)

        self.assertIn("https://example.com/about", extractor.links)
        self.assertIn("https://example.com/contact?source=web", extractor.links)
        self.assertIn("https://other.com/external", extractor.links)
        self.assertIn("https://example.com/static/app.js", extractor.scripts)

        self.assertEqual(len(extractor.forms), 1)
        form = extractor.forms[0]
        self.assertEqual(form["action"], "https://example.com/login")
        self.assertEqual(form["method"], "POST")
        input_names = [inp["name"] for inp in form["inputs"]]
        self.assertEqual(input_names, ["username", "password", "csrf_token"])

    def test_scope_filtering_rejects_external_hosts_and_binaries(self):
        self.assertTrue(_is_in_scope("https://example.com/dashboard", "example.com", "https"))
        self.assertFalse(_is_in_scope("https://sub.example.com/dashboard", "example.com", "https"))
        self.assertFalse(_is_in_scope("https://external.com/", "example.com", "https"))
        self.assertFalse(_is_in_scope("http://example.com/", "example.com", "https"))
        self.assertFalse(_is_in_scope("https://example.com/logo.png", "example.com", "https"))
        self.assertFalse(_is_in_scope("https://example.com/style.css", "example.com", "https"))

    def test_parse_robots_txt(self):
        robots_txt = """
        User-agent: *
        Disallow: /admin/
        Disallow: /private
        Allow: /public/
        Sitemap: https://example.com/sitemap.xml
        """
        res = parse_robots_txt(robots_txt)
        self.assertIn("/admin/", res["disallowed"])
        self.assertIn("/private", res["disallowed"])
        self.assertIn("/public/", res["allowed"])
        self.assertEqual(res["sitemaps"], ["https://example.com/sitemap.xml"])

    def test_parse_sitemap_xml(self):
        sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://example.com/page1</loc></url>
          <url><loc>https://example.com/page2</loc></url>
        </urlset>
        """
        urls = parse_sitemap_xml(sitemap_xml)
        self.assertIn("https://example.com/page1", urls)
        self.assertIn("https://example.com/page2", urls)

    def test_scan_live_nuclei_includes_target_urls(self):
        dest = Destination(
            url="https://example.com/",
            scheme="https",
            host="example.com",
            port=443,
            path="/",
            origin="https://example.com",
            ip="93.184.216.34",
        )
        mock_runner = MagicMock()
        mock_res = MagicMock()
        mock_res.stdout = (
            b'{"template-id": "tech-detect", "matched-at": "https://example.com/subpage", '
            b'"info": {"name": "Tech", "severity": "info"}}\n'
        )
        mock_res.outcome = "completed"
        mock_runner.return_value = mock_res

        scan_live_nuclei(
            dest,
            "93.184.216.34",
            run=mock_runner,
            target_urls=["https://example.com/subpage", "https://example.com/admin"],
        )
        self.assertTrue(mock_runner.called)
        call_args = mock_runner.call_args[0]
        argv = call_args[1]
        self.assertIn("-u", argv)
        # Confirm subpages are passed as -u arguments
        self.assertIn("https://example.com/subpage", argv)
        self.assertIn("https://example.com/admin", argv)


class CrawlerSensitiveProbeGatingTests(unittest.TestCase):
    """F03: the sensitive-file probe is an active request and must not run when not enabled."""

    _dest = Destination(
        "https://example.com/", "https", "example.com", 443, "/", "https://example.com", "example.com"
    )

    def _run(self, probe_sensitive):
        # Keep the spider itself offline: every page fetch returns empty.
        with (
            patch.object(crawler_mod, "_fetch_page", return_value=(404, {}, "")),
            patch.object(crawler_mod, "probe_sensitive_files", return_value=[]) as probe,
        ):
            crawl(self._dest, "93.184.216.34", max_depth=1, max_pages=1, probe_sensitive=probe_sensitive)
        return probe

    def test_probe_not_dispatched_when_disabled(self):
        self._run(probe_sensitive=False).assert_not_called()

    def test_probe_dispatched_when_enabled(self):
        self._run(probe_sensitive=True).assert_called_once()


class CrawlCoverageTruncationTests(unittest.TestCase):
    """Big-site honesty: a crawl that hits its page cap with URLs still queued reports truncation."""

    _dest = Destination(
        "https://example.com/", "https", "example.com", 443, "/", "https://example.com", "example.com"
    )

    def test_truncation_reported_when_page_cap_reached(self):
        body = (
            "<html><body>"
            + "".join(f'<a href="https://example.com/p{i}">p{i}</a>' for i in range(8))
            + "</body></html>"
        )
        with (
            patch.object(crawler_mod, "_fetch_page", return_value=(200, {"content-type": "text/html"}, body)),
            patch.object(crawler_mod, "probe_sensitive_files", return_value=[]),
        ):
            res = crawl(self._dest, "93.184.216.34", max_depth=2, max_pages=3, probe_sensitive=False)
        self.assertTrue(res["coverage_truncated"])
        self.assertEqual(res["pages_visited"], 3)
        self.assertGreater(res["frontier_remaining"], 0)

    def test_no_truncation_when_surface_fits(self):
        with (
            patch.object(crawler_mod, "_fetch_page", return_value=(200, {"content-type": "text/html"}, "<html></html>")),
            patch.object(crawler_mod, "probe_sensitive_files", return_value=[]),
        ):
            res = crawl(self._dest, "93.184.216.34", max_depth=1, max_pages=50, probe_sensitive=False)
        self.assertFalse(res["coverage_truncated"])
        self.assertEqual(res["frontier_remaining"], 0)


if __name__ == "__main__":
    unittest.main()
