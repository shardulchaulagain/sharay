"""CycloneDX SBOM parser (L6): component inventory, and feeding it into the OSV matcher."""

import json
import unittest

from packages.scanner_adapters.integrations.osv import match
from services.source_analysis_worker.sbom import parse_cyclonedx


def sbom(*components):
    return json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": list(components)}
    ).encode()


class CycloneDXParsingTests(unittest.TestCase):
    def test_pypi_and_npm_components_resolve_from_purl(self):
        data = sbom(
            {"type": "library", "name": "requests", "version": "2.28.1", "purl": "pkg:pypi/requests@2.28.1"},
            {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
        )
        components = parse_cyclonedx(data)["components"]
        self.assertEqual(
            {(c["ecosystem"], c["name"], c["version"]) for c in components},
            {("PyPI", "requests", "2.28.1"), ("npm", "lodash", "4.17.21")},
        )

    def test_scoped_npm_purl_is_url_decoded(self):
        data = sbom({"name": "x", "version": "1.0.0", "purl": "pkg:npm/%40scope/pkg@1.0.0"})
        self.assertEqual(parse_cyclonedx(data)["components"][0]["name"], "@scope/pkg")

    def test_unusable_or_unsupported_components_are_listed_not_dropped(self):
        data = sbom(
            {"name": "mystery", "version": "1.0"},  # no purl
            {"name": "cargo-thing", "version": "1.0", "purl": "pkg:cargo/thing@1.0"},  # unsupported ecosystem
            {"name": "noversion", "purl": "pkg:pypi/noversion"},  # no version in purl
        )
        parsed = parse_cyclonedx(data)
        self.assertEqual(parsed["components"], [])
        self.assertEqual(len(parsed["unresolved"]), 3)

    def test_a_non_cyclonedx_document_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_cyclonedx(json.dumps({"components": []}).encode())

    def test_an_unresolved_purl_does_not_echo_its_credentialled_qualifiers(self):
        data = sbom({"name": "x", "purl": "pkg:generic/x?download_url=https://user:tokenvalue123@h/a.tgz"})
        echoed = parse_cyclonedx(data)["unresolved"][0]["component"]
        self.assertNotIn("tokenvalue123", echoed)
        self.assertNotIn("@h", echoed)
        self.assertEqual(echoed, "pkg:generic/x")

    def test_version_is_url_decoded_so_it_can_match(self):
        data = sbom({"name": "d", "version": "x", "purl": "pkg:pypi/django@1.11.1%2Blocal"})
        self.assertEqual(parse_cyclonedx(data)["components"][0]["version"], "1.11.1+local")

    def test_a_control_character_in_a_name_makes_the_component_unusable(self):
        data = sbom({"name": "d", "version": "x", "purl": "pkg:pypi/req%00uests@1.0"})
        parsed = parse_cyclonedx(data)
        self.assertEqual(parsed["components"], [])
        self.assertEqual(len(parsed["unresolved"]), 1)

    def test_a_resolved_component_purl_does_not_echo_credentialled_qualifiers(self):
        data = sbom(
            {
                "name": "requests",
                "version": "2.28.1",
                "purl": "pkg:pypi/requests@2.28.1?vcs_url=https://user:tokenvalue123@h/a.tgz",
            }
        )
        purl = parse_cyclonedx(data)["components"][0]["purl"]
        self.assertNotIn("tokenvalue123", purl)
        self.assertEqual(purl, "pkg:pypi/requests@2.28.1")

    def test_names_and_versions_must_fit_the_ecosystem_grammar(self):
        bad = parse_cyclonedx(
            sbom(
                {"name": "a", "version": "1", "purl": "pkg:pypi/requests@not-a-pep440-version"},
                {"name": "b", "version": "1", "purl": "pkg:npm/ns/extra/pkg@1.2.3-"},
            )
        )
        self.assertEqual(bad["components"], [])
        self.assertEqual(len(bad["unresolved"]), 2)
        # A valid PEP 440 / SemVer pair still resolves.
        good = parse_cyclonedx(sbom({"name": "a", "version": "1", "purl": "pkg:pypi/requests@2.28.1"}))
        self.assertEqual(len(good["components"]), 1)

    def test_a_credential_shaped_package_name_is_never_echoed(self):
        token = "sk-proj-" + "a" * 48
        for body in (f"pypi/{token}", f"npm/{token}", f"npm/%40{token}/fixture"):
            parsed = parse_cyclonedx(sbom({"purl": f"pkg:{body}@1.2.3"}))
            self.assertNotIn(token, json.dumps(parsed))  # not in name, not in the echoed purl
            self.assertEqual(parsed["components"], [])  # unusable identity -> unresolved, not matched

    def test_pypi_names_dedup_case_and_separator_insensitively(self):
        data = sbom(
            {"name": "R", "version": "1.0", "purl": "pkg:pypi/Requests@1.0"},
            {"name": "r", "version": "1.0", "purl": "pkg:pypi/requests@1.0"},
        )
        components = parse_cyclonedx(data)["components"]
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0]["name"], "requests")


class SbomFeedsOsvTests(unittest.TestCase):
    def test_sbom_components_match_an_osv_advisory(self):
        components = parse_cyclonedx(
            sbom({"name": "requests", "version": "2.19.0", "purl": "pkg:pypi/requests@2.19.0"})
        )["components"]
        advisory = json.dumps(
            {
                "id": "OSV-TEST-1",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "requests"},
                        "ranges": [
                            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}
                        ],
                    }
                ],
            }
        ).encode()
        result = match(advisory, components)
        self.assertEqual([f["advisory"] for f in result["findings"]], ["OSV-TEST-1"])


if __name__ == "__main__":
    unittest.main()
