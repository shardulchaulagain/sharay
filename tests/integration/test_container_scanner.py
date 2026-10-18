"""Container/IaC analyzer (L6): Dockerfile and Kubernetes PodSpec checks over a staged tree."""

import tempfile
import unittest
from pathlib import Path

from services.source_analysis_worker.containers import (
    scan,
    scan_dockerfile_content,
    scan_k8s_manifest_dict,
)

SECRET = "sk-proj-" + "0123456789abcdef" * 3  # token-shaped literal, not a real credential


class DockerfileChecks(unittest.TestCase):
    def test_insecure_dockerfile_flags_each_issue(self):
        insecure = (
            "FROM python:latest\n"
            f"ENV DB_PASSWORD={SECRET}\n"
            "RUN curl -sSL https://install.example.com | bash\n"
            'CMD ["python", "app.py"]\n'
        )
        findings = scan_dockerfile_content(insecure, "Dockerfile")
        rule_ids = {f["rule_id"] for f in findings}
        self.assertEqual(
            {
                "DOCKER_UNPINNED_IMAGE",
                "DOCKER_SECRET_IN_ENV",
                "DOCKER_CURL_PIPE_SHELL",
                "DOCKER_CONTAINER_RUNS_AS_ROOT",
                "DOCKER_MISSING_HEALTHCHECK",
            },
            rule_ids,
        )

    def test_secret_value_is_redacted_not_echoed(self):
        findings = scan_dockerfile_content(f"FROM alpine:3.19\nENV API_TOKEN={SECRET}\n", "Dockerfile")
        secret_finding = next(f for f in findings if f["rule_id"] == "DOCKER_SECRET_IN_ENV")
        self.assertNotIn(SECRET, secret_finding["description"])

    def test_untrusted_image_name_is_sanitized(self):
        findings = scan_dockerfile_content("FROM evil\x07image\x00name\n", "Dockerfile")
        unpinned = next(f for f in findings if f["rule_id"] == "DOCKER_UNPINNED_IMAGE")
        self.assertNotIn("\x07", unpinned["description"])
        self.assertNotIn("\x00", unpinned["description"])

    def test_final_stage_governs_in_a_multi_stage_build(self):
        # A non-root USER in an earlier stage must not mask a root final stage.
        df = "FROM python:3.12 AS build\nUSER app\nHEALTHCHECK CMD true\nFROM python:3.12\nRUN echo hi\n"
        rule_ids = {f["rule_id"] for f in scan_dockerfile_content(df)}
        self.assertIn("DOCKER_CONTAINER_RUNS_AS_ROOT", rule_ids)
        self.assertIn("DOCKER_MISSING_HEALTHCHECK", rule_ids)

    def test_from_platform_flag_is_not_mistaken_for_the_image(self):
        df = "FROM --platform=linux/amd64 python:3.12\nUSER app\nHEALTHCHECK CMD true\n"
        rule_ids = {f["rule_id"] for f in scan_dockerfile_content(df)}
        self.assertNotIn("DOCKER_UNPINNED_IMAGE", rule_ids)

    def test_user_root_with_a_group_still_counts_as_root(self):
        df = "FROM python:3.12\nHEALTHCHECK CMD true\nUSER root:root\n"
        self.assertIn("DOCKER_CONTAINER_RUNS_AS_ROOT", {f["rule_id"] for f in scan_dockerfile_content(df)})
        df0 = "FROM python:3.12\nHEALTHCHECK CMD true\nUSER 0:0\n"
        self.assertIn("DOCKER_CONTAINER_RUNS_AS_ROOT", {f["rule_id"] for f in scan_dockerfile_content(df0)})

    def test_a_stage_alias_reference_is_not_flagged_as_an_unpinned_image(self):
        df = "FROM python:3.12 AS builder\nUSER app\nHEALTHCHECK CMD true\nFROM builder\nUSER app\nHEALTHCHECK CMD true\n"
        self.assertNotIn("DOCKER_UNPINNED_IMAGE", {f["rule_id"] for f in scan_dockerfile_content(df)})

    def test_registry_port_is_not_mistaken_for_a_tag(self):
        # registry:5000/app is untagged -> unpinned; registry:5000/app:1.0 is pinned.
        self.assertIn(
            "DOCKER_UNPINNED_IMAGE",
            {f["rule_id"] for f in scan_dockerfile_content("FROM registry.example:5000/app\n")},
        )
        self.assertNotIn(
            "DOCKER_UNPINNED_IMAGE",
            {
                f["rule_id"]
                for f in scan_dockerfile_content(
                    "FROM registry.example:5000/app:1.0\nUSER a\nHEALTHCHECK CMD true\n"
                )
            },
        )

    def test_a_stage_built_from_a_named_stage_inherits_user_and_healthcheck(self):
        df = "FROM python:3.12 AS builder\nUSER app\nHEALTHCHECK CMD true\nFROM builder\n"
        ids = {f["rule_id"] for f in scan_dockerfile_content(df)}
        self.assertNotIn("DOCKER_CONTAINER_RUNS_AS_ROOT", ids)
        self.assertNotIn("DOCKER_MISSING_HEALTHCHECK", ids)

    def test_last_healthcheck_directive_in_a_stage_wins(self):
        none_then_cmd = {
            f["rule_id"]
            for f in scan_dockerfile_content("FROM x:1\nUSER a\nHEALTHCHECK NONE\nHEALTHCHECK CMD true\n")
        }
        self.assertNotIn("DOCKER_HEALTHCHECK_DISABLED", none_then_cmd)
        self.assertNotIn("DOCKER_MISSING_HEALTHCHECK", none_then_cmd)
        cmd_then_none = {
            f["rule_id"]
            for f in scan_dockerfile_content("FROM x:1\nUSER a\nHEALTHCHECK CMD true\nHEALTHCHECK NONE\n")
        }
        self.assertIn("DOCKER_HEALTHCHECK_DISABLED", cmd_then_none)

    def test_healthcheck_none_is_flagged_as_disabled_not_missing(self):
        ids = {f["rule_id"] for f in scan_dockerfile_content("FROM x:1\nUSER a\nHEALTHCHECK NONE\n")}
        self.assertIn("DOCKER_HEALTHCHECK_DISABLED", ids)
        self.assertNotIn("DOCKER_MISSING_HEALTHCHECK", ids)

    def test_no_local_user_is_a_hint_not_a_definitive_root_claim(self):
        hint = next(
            f
            for f in scan_dockerfile_content("FROM x:1\nHEALTHCHECK CMD true\n")
            if f["rule_id"] == "DOCKER_CONTAINER_RUNS_AS_ROOT"
        )
        self.assertEqual(hint["confidence"], "medium")
        explicit = next(
            f
            for f in scan_dockerfile_content("FROM x:1\nUSER root\nHEALTHCHECK CMD true\n")
            if f["rule_id"] == "DOCKER_CONTAINER_RUNS_AS_ROOT"
        )
        self.assertEqual(explicit["confidence"], "confirmed")

    def test_null_k8s_resource_limits_count_as_missing(self):
        doc = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "containers": [
                    {
                        "name": "c",
                        "securityContext": {"readOnlyRootFilesystem": True},
                        "resources": {"limits": {"cpu": None, "memory": None}},
                    }
                ]
            },
        }
        self.assertIn("K8S_MISSING_RESOURCE_LIMITS", {f["rule_id"] for f in scan_k8s_manifest_dict(doc)})

    def test_hardened_dockerfile_has_no_findings(self):
        hardened = (
            "FROM python:3.13.1-slim@sha256:" + "e3b0c442" * 8 + "\n"
            "RUN groupadd -r app && useradd -r -g app app\n"
            "USER app\n"
            'HEALTHCHECK CMD python -c "import sys; sys.exit(0)"\n'
            'CMD ["python", "app.py"]\n'
        )
        self.assertEqual(scan_dockerfile_content(hardened, "Dockerfile"), [])


class K8sChecks(unittest.TestCase):
    def test_insecure_manifest_flags_each_issue(self):
        doc = {
            "kind": "Deployment",
            "metadata": {"name": "vulnerable-app"},
            "spec": {
                "template": {
                    "spec": {
                        "hostNetwork": True,
                        "containers": [{"name": "web", "securityContext": {"privileged": True}}],
                    }
                }
            },
        }
        rule_ids = {f["rule_id"] for f in scan_k8s_manifest_dict(doc, "deploy.yaml")}
        self.assertEqual(
            {
                "K8S_HOST_NETWORK",
                "K8S_PRIVILEGED_CONTAINER",
                "K8S_WRITABLE_ROOT_FILESYSTEM",
                "K8S_MISSING_RESOURCE_LIMITS",
            },
            rule_ids,
        )

    def test_hardened_manifest_has_no_findings(self):
        doc = {
            "kind": "Deployment",
            "metadata": {"name": "secure-app"},
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "web",
                                "securityContext": {"privileged": False, "readOnlyRootFilesystem": True},
                                "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
                            }
                        ]
                    }
                }
            },
        }
        self.assertEqual(scan_k8s_manifest_dict(doc, "secure.yaml"), [])

    def test_init_containers_are_checked_too(self):
        doc = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"initContainers": [{"name": "setup", "securityContext": {"privileged": True}}]},
        }
        rule_ids = {f["rule_id"] for f in scan_k8s_manifest_dict(doc, "pod.yaml")}
        self.assertIn("K8S_PRIVILEGED_CONTAINER", rule_ids)

    def test_non_dict_or_specless_manifest_is_empty_not_a_crash(self):
        self.assertEqual(scan_k8s_manifest_dict("not a dict"), [])
        self.assertEqual(scan_k8s_manifest_dict({"kind": "ConfigMap"}), [])


class TreeWalk(unittest.TestCase):
    def test_scan_finds_dockerfiles_and_reports_relative_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "svc").mkdir()
            (root / "Dockerfile").write_text("FROM python:latest\n")
            (root / "svc" / "Dockerfile.prod").write_text(
                "FROM node:latest\nUSER node\nHEALTHCHECK CMD true\n"
            )
            (root / "node_modules").mkdir()
            (root / "node_modules" / "Dockerfile").write_text("FROM x:latest\n")  # skipped folder
            result = scan(root)
        self.assertEqual(set(result["files"]), {"Dockerfile", "svc/Dockerfile.prod"})
        self.assertFalse(result["truncated"])
        paths = {f["path"] for f in result["findings"]}
        self.assertEqual(paths, {"Dockerfile", "svc/Dockerfile.prod"})


if __name__ == "__main__":
    unittest.main()
