"""Adapter robustness evaluation (L8): every parser entrypoint must survive hostile input.

A single battery over all of Claude's parser/validator entrypoints, asserting two invariants that
the Codex/Gemini cross-review repeatedly probed: (1) malformed or wrong-typed input raises a clean
ValueError (its own typed error is a ValueError subclass) rather than crashing with TypeError /
KeyError / RecursionError or returning something broken; (2) a recognised credential is never
echoed into any result field. These hold because the shared helpers `shown`/`label` redact and the
entrypoints validate their inputs; this test keeps that true as the adapters change.
"""

import json
import unittest

from packages.scanner_adapters.integrations import browser, dns, metasploit, normalize, recon, tls
from services.source_analysis_worker import containers, sbom

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

# Entrypoints that take a bytes report.
_BYTES_PARSERS = (
    metasploit.parse_metasploit_catalog,
    metasploit.parse_metasploit_auxiliary_report,
    metasploit.parse_metasploit_sessions,
    sbom.parse_cyclonedx,
)


class HostileInputTests(unittest.TestCase):
    def test_bytes_parsers_reject_none_wrong_type_and_junk(self):
        for parse in _BYTES_PARSERS:
            for bad in (
                None,
                "a string not bytes",
                123,
                b"{not json",
                b"[]" * 0 + b"not",
                b'"a bare string"',
            ):
                with self.assertRaises(ValueError, msg=f"{parse.__name__}({bad!r})"):
                    parse(bad)

    def test_structured_parsers_reject_none_and_wrong_shapes(self):
        cases = (
            (tls.parse_peer_certificate, None),
            (tls.parse_peer_certificate, {"subject": "nope"}),
            (dns.parse_records, None),
            (dns.parse_records, [{"name": None, "type": "A", "data": "203.0.113.5"}]),
            (recon.collect_assets, None),
            (recon.collect_assets, [{"hostnames": ["x.test"]}]),  # no source
            (browser.validate_workflow, None),
            (browser.validate_workflow, [{"verb": "evaluate", "script": "x"}]),
        )
        for fn, bad in cases:
            with self.assertRaises(ValueError, msg=f"{fn.__name__}({bad!r})"):
                fn(bad)

    def test_a_recognised_credential_is_never_echoed(self):
        # Each call feeds the token through a field that reaches a result, and asserts it is redacted.
        outputs = [
            json.dumps(
                metasploit.parse_metasploit_catalog(
                    json.dumps(
                        {
                            "modules": [
                                {
                                    "fullname": "auxiliary/scanner/x",
                                    "type": "auxiliary",
                                    "rank": "normal",
                                    "check_supported": True,
                                    "name": TOKEN,
                                    "references": [],
                                }
                            ]
                        }
                    ).encode()
                )
            ),
            json.dumps(dns.parse_records([{"name": "x.test", "type": "TXT", "data": f"v=spf1 {TOKEN}"}])),
            json.dumps(containers.scan_dockerfile_content(f"FROM x:1\nENV API_KEY={TOKEN}\n", "D")),
            json.dumps(
                sbom.parse_cyclonedx(
                    json.dumps(
                        {"bomFormat": "CycloneDX", "components": [{"purl": f"pkg:pypi/{TOKEN}@1.0"}]}
                    ).encode()
                )
            ),
        ]
        for out in outputs:
            self.assertNotIn(TOKEN, out)

    def test_normalize_rejects_an_unknown_tool(self):
        with self.assertRaises(ValueError):
            normalize.normalize_parsed_finding("not-a-tool", {})


if __name__ == "__main__":
    unittest.main()
