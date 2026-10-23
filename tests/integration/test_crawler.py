"""Unit tests for the in-scope web crawler and HTML extractor."""

import unittest
from unittest.mock import MagicMock, patch

from packages.scanner_adapters import Destination, scan_live_nuclei
from packages.scanner_adapters.integrations import crawler as crawler_mod
from packages.scanner_adapters.integrations.crawler import (
    _HTMLStructureExtractor,
    _is_in_scope,
    crawl,
    parse_robots_txt,
    parse_sitemap_xml,
)


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


if __name__ == "__main__":
    unittest.main()
