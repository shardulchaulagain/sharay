"""Requester regression: a named prior stage retains its static USER and HEALTHCHECK."""

import unittest

from services.source_analysis_worker.containers import scan_dockerfile_content


class StageInheritanceTests(unittest.TestCase):
    def test_later_healthcheck_cmd_replaces_none(self):
        rows = scan_dockerfile_content("FROM python:3.12\nUSER app\nHEALTHCHECK NONE\nHEALTHCHECK CMD true\n")
        rules = {row["rule_id"] for row in rows}
        self.assertNotIn("DOCKER_HEALTHCHECK_DISABLED", rules)
        self.assertNotIn("DOCKER_MISSING_HEALTHCHECK", rules)

    def test_named_stage_inherits_nonroot_user_and_healthcheck(self):
        rows = scan_dockerfile_content(
            "FROM python:3.12 AS builder\nUSER app\nHEALTHCHECK CMD true\nFROM builder\n"
        )
        rules = {row["rule_id"] for row in rows}
        self.assertNotIn("DOCKER_CONTAINER_RUNS_AS_ROOT", rules)
        self.assertNotIn("DOCKER_MISSING_HEALTHCHECK", rules)


if __name__ == "__main__":
    unittest.main()
