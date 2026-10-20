"""Sector O7: specialized tool belt (ffuf/dalfox/katana/interactsh) + sqlmap adapter.

Argv building is safe and bounded; parsers turn real tool output into the house finding shape;
the dispatcher runs tools over an injected runner and skips honestly when a tool is unavailable
(never fabricating results).
"""

from __future__ import annotations

import unittest

from packages.scanner_adapters.integrations import toolbelt
from packages.scanner_adapters.integrations.sqlmap import build_safe_sqlmap_command
from packages.security_policies import Destination


class ArgvAndParseTest(unittest.TestCase):
    def test_argv_is_safe_and_bounded(self):
        ffuf = toolbelt.build_ffuf_argv("http://t/", "t", "1.2.3.4")
        self.assertIn("http://t/FUZZ", ffuf)
        self.assertIn("-rate", ffuf)
        self.assertNotIn("-recursion", ffuf)  # no unbounded recursion

        dalfox = toolbelt.build_dalfox_argv("http://t/?q=1")
        self.assertEqual(dalfox[:2], ["url", "http://t/?q=1"])
        self.assertIn("--format", dalfox)

        katana = toolbelt.build_katana_argv("http://t/", depth=99)
        self.assertIn("-jsonl", katana)
        self.assertIn("5", katana)  # depth clamped to 5

    def test_parse_ffuf_filters_noise_and_flags_sensitive(self):
        data = b'{"results":[{"input":{"FUZZ":"admin"},"status":200,"length":42,"url":"http://t/admin"},{"input":{"FUZZ":"missing"},"status":404,"length":0,"url":"http://t/missing"}]}'
        f = toolbelt.parse_ffuf(data, default_target_url="http://t/")["findings"]
        self.assertEqual(len(f), 1)  # 404 filtered out
        self.assertEqual(f[0]["severity"], "high")  # /admin at 200 is sensitive
        self.assertEqual(f[0]["status"], "suspected")

    def test_parse_dalfox_xss(self):
        data = b'[{"type":"V","severity":"high","cwe":"CWE-79","data":"http://t/?q=<script>","param":"q","payload":"<script>","evidence":"reflected"}]'
        f = toolbelt.parse_dalfox(data, default_target_url="http://t/")["findings"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["category"], "cross_site_scripting")
        self.assertEqual(f[0]["cwe_id"], "CWE-79")
        self.assertEqual(f[0]["poc"]["parameter"], "q")

    def test_parse_katana_dedups_urls(self):
        data = b'{"endpoint":"http://t/a"}\n{"request":{"endpoint":"http://t/b"}}\n{"endpoint":"http://t/a"}\nnotjson'
        self.assertEqual(toolbelt.parse_katana(data), ["http://t/a", "http://t/b"])

    def test_parse_interactsh(self):
        data = b'{"protocol":"dns","unique-id":"abc","remote-address":"1.2.3.4"}'
        recs = toolbelt.parse_interactsh(data)
        self.assertEqual(recs[0]["protocol"], "dns")
        self.assertEqual(recs[0]["source_ip"], "1.2.3.4")

    def test_sqlmap_argv_is_safe(self):
        cmd = build_safe_sqlmap_command("http://t/?id=1", "id")
        self.assertIsInstance(cmd, list)
        self.assertTrue(any("http://t/?id=1" in str(c) for c in cmd))
        self.assertFalse(
            any("--os-shell" in str(c) or "--os-pwn" in str(c) for c in cmd)
        )  # no destructive flags


class _Res:
    def __init__(self, out: bytes):
        self.stdout = out


class DispatcherTest(unittest.TestCase):
    def _dest(self):
        return Destination(
            "http://t.example/", "http", "t.example", 80, "/", "http://t.example", "93.184.216.34"
        )

    def test_dispatcher_runs_tools_and_normalizes(self):
        ffuf = (
            b'{"results":[{"input":{"FUZZ":"admin"},"status":200,"length":1,"url":"http://t.example/admin"}]}'
        )
        dalfox = b'[{"type":"V","severity":"high","data":"http://t.example/?q=<script>","param":"q"}]'
        katana = b'{"endpoint":"http://t.example/x"}'

        def runner(image, argv, **kw):
            if "ffuf" in image:
                return _Res(ffuf)
            if "dalfox" in image:
                return _Res(dalfox)
            if "katana" in image:
                return _Res(katana)
            raise RuntimeError("no image")

        res = toolbelt.run_toolbelt(self._dest(), "93.184.216.34", ["ffuf", "dalfox", "katana"], run=runner)
        cats = {f["category"] for f in res["findings"]}
        self.assertIn("content_discovery", cats)
        self.assertIn("cross_site_scripting", cats)
        self.assertEqual(res["urls"], ["http://t.example/x"])

    def test_dispatcher_skips_unavailable_tool_without_fabricating(self):
        def bad_runner(*a, **k):
            raise RuntimeError("image not pulled")

        res = toolbelt.run_toolbelt(self._dest(), "93.184.216.34", ["ffuf"], run=bad_runner)
        self.assertEqual(res["findings"], [])
        self.assertTrue(any(c["status"] == "skipped" for c in res["checks"]))


if __name__ == "__main__":
    unittest.main()
