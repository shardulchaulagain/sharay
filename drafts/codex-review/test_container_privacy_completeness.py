"""Requester acceptance for safe container output and truthful clipped coverage."""

import json
import tempfile
import unittest
from pathlib import Path

from packages.secret_patterns import redact_tokens
from services.source_analysis_worker.containers import scan, scan_dockerfile_content, scan_k8s_manifest_dict


class ContainerOutputTests(unittest.TestCase):
    def test_sensitive_variable_values_are_not_echoed_or_sampled(self):
        ordinary = "owned_fixture_password_only"
        provider = "github_pat_" + "a" * 82
        self.assertNotEqual(redact_tokens(provider, "[REDACTED]"), provider)
        for value in (ordinary, provider):
            with self.subTest(kind="ordinary" if value == ordinary else "provider"):
                rows = scan_dockerfile_content("FROM fixture:1.0\nENV DB_PASSWORD=" + value + "\n")
                self.assertTrue(any(row["rule_id"] == "DOCKER_SECRET_IN_ENV" for row in rows))
                encoded = json.dumps(rows)
                self.assertTrue(
                    value not in encoded and value[:80] not in encoded, "Credential sample echoed"
                )

    def test_identity_fields_redact_recognized_tokens_before_shortening(self):
        token = "AKIA" + "A" * 16
        self.assertNotEqual(redact_tokens(token, "[REDACTED]"), token)
        cases = {
            "image": scan_dockerfile_content("FROM " + token + ":latest\n"),
            "path": scan_dockerfile_content("FROM fixture:1.0\n", token + "/Dockerfile"),
            "manifest": scan_k8s_manifest_dict(
                {"kind": "Pod", "metadata": {"name": token}, "spec": {"containers": [{"name": token}]}}
            ),
        }
        for kind, rows in cases.items():
            with self.subTest(kind=kind):
                self.assertTrue(rows, "Existing configuration hints must remain available")
                self.assertTrue(token not in json.dumps(rows), "Known token echoed from an identity field")

    def test_per_file_finding_limit_marks_incomplete_coverage(self):
        with tempfile.TemporaryDirectory(prefix="container-acceptance-") as folder:
            Path(folder, "Dockerfile").write_text("FROM fixture:1.0\n" + "ENV TOKEN=fixture\n" * 2001)
            result = scan(folder)
        self.assertTrue(result["findings"], "Analysis must retain bounded findings")
        self.assertLessEqual(len(result["findings"]), 2000)
        self.assertTrue(result["truncated"], "Dropped per-file findings must mark incomplete coverage")


if __name__ == "__main__":
    unittest.main()
